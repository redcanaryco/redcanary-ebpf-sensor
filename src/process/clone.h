#pragma once

#include "vmlinux.h"

#include "../common/common.h"
#include "push_message.h"

typedef struct {
  u64 pid_tgid;
  u64 start_ktime_ns;
  clone_info_t clone_info;
} incomplete_clone_t;

// A map of clones that have started (a kprobe) but are yet to finish
// (the kretprobe).
struct bpf_map_def SEC("maps/incomplete_clone") incomplete_clones = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(incomplete_clone_t),
  .max_entries = 8 * 1024,
  .pinning = 0,
  .namespace = "",
};

// handles the kprobe of clone-like syscalls (fork, vfork, clone, clone3)
static __always_inline void enter_clone(void *ctx, process_message_type_t pm_type, unsigned long flags)
{
  // we do not care about threads spawning; ignore clones that would
  // share the same thread group as the parent.
  if (flags & CLONE_THREAD)
    return;

  u64 pid_tgid = bpf_get_current_pid_tgid();
  incomplete_clone_t event = {0};
  event.pid_tgid = pid_tgid;
  event.clone_info.flags = flags;
  event.start_ktime_ns = bpf_ktime_get_ns();

  int ret = bpf_map_update_elem(&incomplete_clones, &pid_tgid, &event, BPF_ANY);
  if (ret < 0)
  {
    process_message_t pm = {0};
    pm.type = PM_WARNING;
    pm.u.warning_info.pid_tgid = pid_tgid;
    pm.u.warning_info.message_type.process = pm_type;
    pm.u.warning_info.code = W_UPDATE_MAP_ERROR;
    pm.u.warning_info.info.err = ret;

    push_message(ctx, &pm);

    return;
  }

  return;
}

// handles the kretprobe of clone-like syscalls (fork, vfork, clone, clone3)
static __always_inline void exit_clone(struct syscalls_exit_args *ctx, pprocess_message_t pm, process_message_type_t pm_type)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  load_event(incomplete_clones, pid_tgid, incomplete_clone_t);

  int retcode = ctx->ret;
  if (retcode < 0)
    goto Done;

  void *ts = (void *)bpf_get_current_task();
  int ret = fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32);
  if (ret > 0) return;
  if (ret < 0) goto EmitWarning;

  pm->type = pm_type;
  pm->u.syscall_info.mono_ns = event.start_ktime_ns;
  pm->u.syscall_info.data.clone_info = event.clone_info;
  pm->u.syscall_info.retcode = retcode;

  push_message(ctx, pm);

  goto Done;

 EventMismatch:;
  error_info_t info = {0};
  info.stored_pid_tgid = event.pid_tgid;
  set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:;
  push_warning(ctx, pm, pm_type);

 Done:;
  // only delete at the every end so the event pointer above is
  // valid for the duration of this function.
  bpf_map_delete_elem(&incomplete_clones, &pid_tgid);
  return;

 NoEvent:;
  return;
}

// adds ts->tgid as the child_pid to an incomplete clone event for the
// current task
static __always_inline void add_childpid(void *ts)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  load_event(incomplete_clones, pid_tgid, incomplete_clone_t);

  // get the true pid
  u32 npid = 0;
  if (read_field(ts, CRC_TASK_STRUCT_PID, &npid, sizeof(npid)) < 0) {
    // don't bother emitting a warning; worst case we can use the retcode
    return;
  }

  u32 ntgid = 0;
  if (read_field(ts, CRC_TASK_STRUCT_TGID, &ntgid, sizeof(ntgid)) < 0) {
    // don't bother emitting a warning; worst case we can use the retcode
    return;
  }

  // this means that this task_struct belongs to a non-main
  // thread. We do not care about new threads being spawned so exit
  // early.
  if (npid != ntgid)
  {
    // the kretprobe shouldn't care about it either
    bpf_map_delete_elem(&incomplete_clones, &pid_tgid);
    return;
  }

  // deliberately not deleting from the map - we'll let the
  // kretprobe do that and send the event
  event.clone_info.child_pid = ntgid;
  // we copied the event so we need to manually update it
  bpf_map_update_elem(&incomplete_clones, &pid_tgid, &event, BPF_ANY);

  return;

  // let the kretprobe return the error as that has more information
 EventMismatch:;
 NoEvent:;
}
