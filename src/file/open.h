#include <asm/ptrace.h>
#include "common/bpf_helpers.h"

typedef struct
{
  u64 pid_tgid;
  void *create_dentry; // dentry of the created object
} create_dentry_t;

struct bpf_map_def SEC("maps/create_dentries") create_dentries = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(create_dentry_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

// Caches the dentry of a created object to be used during tracing of open events
// to determine if the file was created or existed previously.
static __always_inline void cache_dentry(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  create_dentry_t *create_dentry = (create_dentry_t *)bpf_map_lookup_elem(&create_dentries, &pid_tgid);
  if (create_dentry != NULL)
    return;

  struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);
  if (dentry == NULL)
    return;

  create_dentry_t event = {0};
  event.pid_tgid = pid_tgid;
  event.create_dentry = dentry;
}
