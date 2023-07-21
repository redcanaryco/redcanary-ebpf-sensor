#pragma once

#include "../common/buffer.h"
#include "../common/common.h"
#include "../common/helpers.h"
#include "../common/path.h"
#include "../common/types.h"
#include "./push_message.h"

// 256 is BINPRM_BUF_SIZE starting on kernels 5.1+.
#define BINPRM_BUF_SIZE 256

// the kernel deliberately fails if it has to rewrite it more than 4 times
#define MAX_INTERPRETERS 4

#define PATH_MAX 4096

typedef struct
{
  u32 pid;

  struct {
    // relative path to the script. This string has already been
    // copied into kernel space and it is not freed during
    // interpreter finding thus making it safe to use directly
    char *path;
    file_info_t identity;
  } file;

  file_info_t interpreters[MAX_INTERPRETERS];
} script_t;

// A map containing script information for currently running exec*
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

// A map of file identities -> interpreter paths. We do not currently
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

typedef struct {
  u32 pid;
  file_info_t interpreter;
} relative_file_info_t;

// A map of file identities + pid -> interpreter paths that are
// relative to the cwd of the related process. This map is used for
// the rare cases where a script uses a relative path in its
// interpreter line (e.g., `#!./my_special_interpreter`).
struct bpf_map_def SEC("maps/rel_interpreters") rel_interpreters = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(relative_file_info_t),
  .value_size = sizeof(interpreter_path_t),
  .max_entries = 128, // TODO: should we expand oxidebpf to allow scaling based on # cpus?
  .pinning = 0,
  .namespace = "",
};

static __always_inline void enter_script(struct pt_regs *ctx, void *bprm) {
  if (!offset_loaded()) return;

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
  int ret = 0;
  load_event(scripts, pid, script_t);

  // nothing else to do
  if (filename == interp) return;

  file_info_t *new_interpreter = NULL;
#pragma unroll MAX_INTERPRETERS
  for (int i = 0; i < MAX_INTERPRETERS; i++) {
    if (event.interpreters[i].inode != 0) continue;

    new_interpreter = &event.interpreters[i];
    break;
  }

  if (new_interpreter == NULL) {
    set_empty_local_warning(W_INTERP_SLOT);
    goto EmitWarning;
  }

  if (file_info_from_file(file, new_interpreter) < 0) goto EmitWarning;
  relative_file_info_t rel_interpreter = {0};
  rel_interpreter.pid = pid;
  rel_interpreter.interpreter = *new_interpreter;

  interpreter_path_t path = {0};

  // skip check if sz == BINPRM_BUF_SIZE. If a future kernel increases
  // the value of BINPRM_BUF_SIZE then we may run into truncation but
  // I don't think we need to worry right now.
  ret = bpf_probe_read_str(&path.path, BINPRM_BUF_SIZE, interp);
  if (ret < 0) {
    set_empty_local_warning(W_READ_PATH_STRING);
    goto EmitWarning;
  }

  if (path.path[0] == '/') {
    ret = bpf_map_update_elem(&interpreters, new_interpreter, &path, BPF_ANY);
    if (ret < 0) {
      error_info_t info = {0};
      info.err = ret;
      set_local_warning(W_UPDATE_MAP_ERROR, info);
      goto EmitWarning;
    }

    // evict older relative path interpreters with this inode +
    // pid. When doing lookup relative interpreters take priority so
    // we need to evict them to prevent errors during double execs
    // that both run scripts.
    bpf_map_delete_elem(&rel_interpreters, &rel_interpreter);
  } else {
    ret = bpf_map_update_elem(&rel_interpreters, &rel_interpreter, &path, BPF_ANY);
    if (ret < 0) {
      error_info_t info = {0};
      info.err = ret;
      set_local_warning(W_UPDATE_MAP_ERROR, info);
      goto EmitWarning;
    }
  }

  goto SaveEvent;

 NoEvent:;
  // first time saving a script for this exec*
  if (filename != interp) {
    // if they don't match but we do not have an existing incomplete
    // event then it most likely means that the program was loaded
    // right in between two load_script calls. We can't really know
    // for sure what information was in the initial load_script so we
    // should just skip this.
    return;
  }

  event = (script_t){0};
  event.pid = pid;
  if (file_info_from_file(file, &event.file.identity) < 0) goto EmitWarning;

  char dev[] = "/dev/fd/";
  char truncated_filename[sizeof(dev)] = {0};
  int sz = bpf_probe_read_str(truncated_filename, sizeof(dev), filename);
  int is_dev_fd_file = 0;
  if (sz == sizeof(dev)) {
    is_dev_fd_file = 1;
#pragma unroll sizeof(dev)
    for (int i = 0; i < sizeof(dev); i++) {
      if (dev[i] != truncated_filename[i]) {
        is_dev_fd_file = 0;
        break;
      }
    }
  }

  // If our filename is /dev/fd/* then the kernel (most likely)
  // allocated the string during the creation of the binprm for an
  // execveat. Because the binprm is de-allocated before the kretprobe
  // for exec* is fired we need to copy that string manually.
  if (is_dev_fd_file) {
    interpreter_path_t path = {0};

    // skip check if sz == BINPRM_BUF_SIZE. In theory this *can*
    // truncate the name in the case of a script launched using
    // execveat that uses both the dirfd and a *really long*
    // pathname. I rather truncate in this extreme edge case instead
    // of incurring the runtime cost for all the normal cases.
    ret = bpf_probe_read_str(&path.path, BINPRM_BUF_SIZE, filename);
    if (ret < 0) {
      set_empty_local_warning(W_READ_PATH_STRING);
      goto EmitWarning;
    }

    ret = bpf_map_update_elem(&interpreters, &event.file.identity, &path, BPF_ANY);
    if (ret < 0) {
      error_info_t info = {0};
      info.err = ret;
      set_local_warning(W_UPDATE_MAP_ERROR, info);
      goto EmitWarning;
    }
  } else {
    event.file.path = filename;
  }

  goto SaveEvent;

 SaveEvent:;
  ret = bpf_map_update_elem(&scripts, &event.pid, &event, BPF_ANY);
  if (ret < 0) {
    error_info_t info = {0};
    info.err = ret;
    set_local_warning(W_UPDATE_MAP_ERROR, info);
    goto EmitWarning;
  }

  return;

 EventMismatch:;
  error_info_t info = {0};
  info.stored_pid_tgid = (((u64) event.pid) << 32) | (event.pid);
  set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:;
  // no room in the stack for a process_message_t; let's use our per-cpu buffer
  u32 key = 0;
  buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
  if (buffer == NULL) return;

  process_message_t *pm = (process_message_t *)buffer;
  push_warning(ctx, pm, PM_SCRIPT);

  return;
}

static __always_inline u64 push_scripts(struct pt_regs *ctx, buf_t *buffer) {
  process_message_t *pm = (process_message_t *)buffer;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u64 event_id = 0;

  load_event(scripts, pid, script_t);

  if (event.interpreters[0].inode == 0) goto Done;
  // clear out the buffer
  __builtin_memset(&pm->u.script_info.scripts, 0, sizeof(pm->u.script_info.scripts));

  pm->type = PM_SCRIPT;
  pm->u.script_info.scripts[0] = event.file.identity;
  pm->u.script_info.buffer_length = sizeof(process_message_t);

  int sz = 0;
  if (event.file.path == NULL) {
    // we didn't save the path because the kernel was going to
    // de-allocate it; look it up in our interpreters map instead. No
    // need to look at the rel_interpreters, it is always an absolute
    // path for the /dev/fd/* case
    interpreter_path_t *intp_path = bpf_map_lookup_elem(&interpreters, &event.file.identity);
    if (intp_path == NULL) {
      write_null_char(buffer, &pm->u.script_info.buffer_length);
    } else {
      sz = write_string(intp_path->path, buffer, &pm->u.script_info.buffer_length, BINPRM_BUF_SIZE);
    }
  } else {
    // the original script file path came from the user; the kernel
    // verifies that the user provided path cannot go beyond
    // PATH_MAX. The total path can still be beyond PATH_MAX once you
    // combine it with the CWD but userspace can take care of that
    sz = write_string(event.file.path, buffer, &pm->u.script_info.buffer_length, PATH_MAX);
  }

  if (sz < 0) goto WriteError;

#pragma unroll MAX_INTERPRETERS
  for (int i = 1; i < MAX_INTERPRETERS; i++) {
    // there is no interpreter which means the last interpreter was
    // the actual executable
    if (event.interpreters[i].inode == 0) break;

    // The last interpreter was a script
    file_info_t *intp_key = &event.interpreters[i - 1];
    pm->u.script_info.scripts[i] = *intp_key;

    relative_file_info_t rel_interpreter = {0};
    rel_interpreter.pid = pid;
    rel_interpreter.interpreter = *intp_key;

    interpreter_path_t *intp_path = bpf_map_lookup_elem(&rel_interpreters, &rel_interpreter);
    if (intp_path == NULL) {
      intp_path = bpf_map_lookup_elem(&interpreters, intp_key);
    }

    if (intp_path == NULL) {
      // we couldn't find the saved path given the file identity. This
      // most likely means we got a *lot* of interpreter scripts in
      // quick succession and made this one be evicted from our LRU
      // cache. This is not an error so just write a null character to
      // tell userspace that we don't have a path for this interpreter
      // and then move on. Do not exit early because at least we still
      // got useful information (e.g., the script path and potentially
      // other interpreters).
      write_null_char(buffer, &pm->u.script_info.buffer_length);
      continue;
    }

    sz = write_string(intp_path->path, buffer, &pm->u.script_info.buffer_length, BINPRM_BUF_SIZE);
    if (sz < 0) goto WriteError;
  }

  event_id = ((u64) pid) << 32 | bpf_get_prandom_u32();
  pm->u.script_info.event_id = event_id;

  push_flexible_message(ctx, pm, pm->u.script_info.buffer_length);
  goto Done;

 WriteError:;
  if (sz == -W_UNEXPECTED) {
    set_empty_local_warning(W_READ_PATH_STRING);
  } else {
    set_empty_local_warning(-sz);
  }

  goto EmitWarning;

 EventMismatch:;
  error_info_t info = {0};
  info.stored_pid_tgid = (((u64) event.pid) << 32) | (event.pid);
  set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:;
  push_warning(ctx, pm, PM_SCRIPT);

 Done:;
  bpf_map_delete_elem(&scripts, &pid);

 NoEvent:;
  return event_id;
}
