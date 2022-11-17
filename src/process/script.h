#include "buffer.h"
#include "../types.h"

// 256 is BINPRM_BUF_SIZE starting on kernels 5.1+.
#define BINPRM_BUF_SIZE 256

// the kernel deliberately fails if it has to rewrite it more than 4 times
#define MAX_INTERPRETERS 4

typedef struct
{
  struct {
    // relative path to the script. This string has already been
    // copied into kernel space and it is not freed during
    // interpreter finding thus making it safe to use directly
    char *path;
    file_info_t identity;
  } file;

  file_info_t interpreters[MAX_INTERPRETERS];
} script_t;

// A map containing script information for currently running exe*c
struct bpf_map_def SEC("maps/scripts") scripts = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(script_t),
  .max_entries = 1024, // TODO: should we expand oxidebpf to allow scaling based on # cpus?
  .pinning = 0,
  .namespace = "",
};

typedef struct {
  char path[BINPRM_BUF_SIZE];
} interpreter_path_t;

// A map of file identities to interpreter paths. We do not currently
// invalidate keys when paths are deleted/renamed so this is meant to
// be inserted and retrieved by different probes corresponding to the
// *same* syscall. In theory this could create a data race if an exec
// starts using an interpreter, the identity->path relation is stored
// here, then before that exec finishes the interpreter is removed, a
// new interpreter is created that re-uses the inode, and then an exec
// starts that utilizes that interpreter. This is an extreme edgecase
// that we are not handling.
struct bpf_map_def SEC("maps/interpreters") interpreters = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(file_info_t),
  .value_size = sizeof(interpreter_path_t),
  .max_entries = 1024,
  .pinning = 0,
  .namespace = "",
};

static __always_inline void enter_script(struct pt_regs *ctx, void *bprm) {
  // filename = bprm->filename
  char *filename = read_field_ptr(bprm, CRC_LINUX_BINPRM_FILENAME);
  if (filename == NULL) goto EmitWarning;

  // interp = bprm->interp
  char *interp = read_field_ptr(bprm, CRC_LINUX_BINPRM_INTERP);
  if (interp == NULL) goto EmitWarning;

  // file = bprm->file
  void *file = read_field_ptr(bprm, CRC_LINUX_BINPRM_FILE);
  if (file == NULL) goto EmitWarning;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  script_t *script = bpf_map_lookup_elem(&scripts, &pid);

  // first time saving a script for this exec*
  if (script == NULL) {
    if (filename != interp) {
      bpf_printk("unexpected state: filename != interp on first load_script");
      return;
    }
    script_t script = {};
    script.file.path = filename;
    if (extract_file_info(file, &script.file.identity) < 0) goto EmitWarning;

    if (bpf_map_update_elem(&scripts, &pid, &script, BPF_ANY) < 0) {
      bpf_printk("failed to insert scripts");
    }

    return;
  }

  // nothing else to do
  if (filename == interp) return;

  file_info_t *new_interpreter = NULL;
#pragma unroll MAX_INTERPRETERS
  for (int i = 0; i < MAX_INTERPRETERS; i++) {
    if (script->interpreters[i].inode != 0) continue;

    new_interpreter = &script->interpreters[i];
    break;
  }

  if (new_interpreter == NULL) {
    bpf_printk("unexpected state; no free slot for interpreter");
    return;
  }

  if (extract_file_info(file, new_interpreter) < 0) goto EmitWarning;

  u32 key = 0;
  buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
  if (buffer == NULL) return;

  interpreter_path_t *path = (interpreter_path_t *)buffer;

  int sz = bpf_probe_read_str(&path->path, BINPRM_BUF_SIZE, interp);
  if (sz < 0) {
    bpf_printk("failed to read interp");
    return;
  } else if (sz == BINPRM_BUF_SIZE) {
    bpf_printk("hit interp size limit");
  }
  if (bpf_map_update_elem(&interpreters, new_interpreter, path, BPF_ANY) < 0) {
    bpf_printk("failed to insert interp path");
  }

  return;

 EmitWarning:;
  process_message_t pm = {0};
  push_warning(ctx, &pm, PM_EXECVE);

  return;
}

static __always_inline void push_scripts(struct pt_regs *ctx, buf_t *buffer) {
  process_message_t *pm = (process_message_t *)buffer;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  script_t *script = bpf_map_lookup_elem(&scripts, &pid);
  if (script == NULL) return;

  if (script->interpreters[0].inode == 0) goto Done;
  // clear out the buffer
  __builtin_memset(&pm->u.script_info.scripts, 0, sizeof(pm->u.script_info.scripts));

  pm->type = PM_SCRIPT;
  pm->u.script_info.scripts[0] = script->file.identity;
  pm->u.script_info.buffer_length = sizeof(process_message_t);

  int sz = write_string(script->file.path, buffer, &pm->u.script_info.buffer_length, 4096);
  if (sz < 0) {
    bpf_printk("failed to write path to buffer");
    goto Done;
  } else if (sz == 4096) {
    bpf_printk("unexpected path max");
  }

#pragma unroll MAX_INTERPRETERS
  for (int i = 1; i < MAX_INTERPRETERS; i++) {
    if (script->interpreters[i].inode == 0) break;

    file_info_t *intp_key = &script->interpreters[i - 1];
    pm->u.script_info.scripts[i] = *intp_key;

    interpreter_path_t *intp_path = bpf_map_lookup_elem(&interpreters, intp_key);
    if (intp_path == NULL) {
      bpf_printk("failed to find interpreter path");
      write_null_char(buffer, &pm->u.script_info.buffer_length);
      continue;
    }

    int sz = write_string(intp_path->path, buffer, &pm->u.script_info.buffer_length, BINPRM_BUF_SIZE);
    if (sz < 0) {
      bpf_printk("failed to write path to buffer");
    }
    /* overflow impossible for sized array not checking */
  }

  push_flexible_message(ctx, pm, pm->u.script_info.buffer_length);

 Done:;
  bpf_map_delete_elem(&scripts, &pid);

  return;
}
