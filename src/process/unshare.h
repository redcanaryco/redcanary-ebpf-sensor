#pragma once

#include "../common.h"
#include "helpers.h"

typedef struct {
  u64 pid_tgid;
  u64 start_ktime_ns;
  int unshare_flags;
} incomplete_unshare_t;

// A map of unshares that have started (a kprobe) but are yet to finish
// (the kretprobe).
struct bpf_map_def SEC("maps/incomplete_unshare") incomplete_unshares = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(incomplete_unshare_t),
  // this is lower than exec or clone because we don't foresee that many concurrent unshares
  .max_entries = 256,
  .pinning = 0,
  .namespace = "",
};

static __always_inline void enter_unshare(struct pt_regs *ctx, int flags)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  incomplete_unshare_t event = {0};
  event.pid_tgid = pid_tgid;
  event.start_ktime_ns = bpf_ktime_get_ns();
  event.unshare_flags = flags;

  int ret = bpf_map_update_elem(&incomplete_unshares, &pid_tgid, &event, BPF_ANY);
  if (ret < 0)
    {
      process_message_t pm = {0};
      pm.type = PM_WARNING;
      pm.u.warning_info.pid_tgid = pid_tgid;
      pm.u.warning_info.message_type.process = PM_UNSHARE;
      pm.u.warning_info.code = W_UPDATE_MAP_ERROR;
      pm.u.warning_info.info.err = ret;

      push_message(ctx, &pm);
    }
}

static __always_inline void exit_unshare(struct pt_regs *ctx, pprocess_message_t pm)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  load_event(incomplete_unshares, pid_tgid, incomplete_unshare_t);

  int retcode = (int)PT_REGS_RC(ctx);
  if (retcode < 0) goto Done;

  void *ts = (void *)bpf_get_current_task();

  int ret = fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32);
  if (ret > 0) goto Done;
  if (ret < 0) goto EmitWarning;

  pm->type = PM_UNSHARE;
  pm->u.syscall_info.mono_ns = event.start_ktime_ns;
  pm->u.syscall_info.data.unshare_flags = event.unshare_flags;
  pm->u.syscall_info.retcode = retcode;

  push_message(ctx, pm);

 Done:;
  // only delete at the very end so the event pointer above is valid
  // for the duration of this function.
  bpf_map_delete_elem(&incomplete_unshares, &pid_tgid);
  return;

 EventMismatch:;
  error_info_t info = {0};
  info.stored_pid_tgid = event.pid_tgid;
  set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:;
  push_warning(ctx, pm, PM_UNSHARE);
  return;

 NoEvent:;
  return;
}
