// SPDX-License-Identifier: GPL-2.0+

#include <linux/kconfig.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>
#include <linux/uio.h>
#include <linux/fcntl.h>
#include "common/bpf_helpers.h"
#include "common/types.h"
#include "common/offsets.h"
#include "common/repeat.h"
#include "common/common.h"

#include "process/clone.h"
#include "process/exec.h"
#include "process/exit.h"
#include "process/unshare.h"

SEC("kprobe/sys_exec_pwd")
int sys_exec_pwd(struct pt_regs *ctx)
{
    process_pwd(ctx);

    return 0;
}

SEC("kretprobe/ret_sys_execve")
int ret_sys_execve(struct pt_regs *ctx)
{
    exit_exec(ctx, PM_EXECVE, bpf_get_current_cgroup_id(), RET_SYS_EXECVE);

    return 0;
}

SEC("kretprobe/ret_sys_execveat")
int ret_sys_execveat(struct pt_regs *ctx)
{
    exit_exec(ctx, PM_EXECVEAT, bpf_get_current_cgroup_id(), RET_SYS_EXECVEAT);

    return 0;
}

SEC("kretprobe/ret_sys_execve_pre_4_18")
int ret_sys_execve_pre_4_18(struct pt_regs *ctx)
{
    exit_exec(ctx, PM_EXECVE, 0, RET_SYS_EXECVE);

    return 0;
}

SEC("kretprobe/ret_sys_execveat_pre_4_18")
int ret_sys_execveat_pre_4_18(struct pt_regs *ctx)
{
    exit_exec(ctx, PM_EXECVEAT, 0, RET_SYS_EXECVEAT);

    return 0;
}

SEC("kprobe/sys_clone_4_8")
#if defined(__TARGET_ARCH_x86)
int BPF_KPROBE_SYSCALL(sys_clone_4_8, unsigned long flags, void __user *stack,
                       int __user *parent_tid, int __user *child_tid, unsigned long tls)
#elif defined(__TARGET_ARCH_arm64)
int BPF_KPROBE_SYSCALL(sys_clone_4_8, unsigned long flags, void __user *stack,
                       int __user *parent_tid, unsigned long tls, int __user *child_tid)
#endif
{
    enter_clone(ctx, PM_CLONE, flags);

    return 0;
}

SEC("kprobe/sys_clone3")
int BPF_KPROBE_SYSCALL(sys_clone3, struct clone_args __user *uargs, size_t size)
{
    u64 flags = 0;
    bpf_probe_read(&flags, sizeof(u64), &uargs->flags);

    enter_clone(ctx, PM_CLONE3, flags);

    return 0;
}

SEC("kretprobe/ret_sys_clone3")
int ret_sys_clone3(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clone(ctx, &sev, PM_CLONE3);
    return 0;
}

// This probe can generically read the pid from a task_struct at any
// point where the first argument is a pointer to a task_struct, the
// event emit is a RETCODE with the correct PID, intended for use with
// tracing fork, clone, etc. It returns early if the task is not a
// main thread (pid != tid).
SEC("kprobe/read_pid_task_struct")
int read_pid_task_struct(struct pt_regs *ctx)
{
    // get passed in task_struct
    void *ts = (void *)PT_REGS_PARM1(ctx);
    add_childpid(ts);

    return 0;
}

SEC("kprobe/sys_fork_4_8")
int BPF_KPROBE_SYSCALL(sys_fork_4_8)
{
    enter_clone(ctx, PM_FORK, SIGCHLD);

    return 0;
}

SEC("kprobe/sys_vfork_4_8")
int BPF_KPROBE_SYSCALL(sys_vfork_4_8)
{
    enter_clone(ctx, PM_VFORK, CLONE_VFORK | CLONE_VM | SIGCHLD);

    return 0;
}

SEC("kretprobe/ret_sys_clone")
int ret_sys_clone(struct pt_regs *ctx)
{
    process_message_t pm = {0};
    exit_clone(ctx, &pm, PM_CLONE);
    return 0;
}

SEC("kretprobe/ret_sys_fork")
int ret_sys_fork(struct pt_regs *ctx)
{
    process_message_t pm = {0};
    exit_clone(ctx, &pm, PM_FORK);
    return 0;
}

SEC("kretprobe/ret_sys_vfork")
int ret_sys_vfork(struct pt_regs *ctx)
{
    process_message_t pm = {0};
    exit_clone(ctx, &pm, PM_VFORK);
    return 0;
}

SEC("kprobe/sys_unshare_4_8")
int BPF_KPROBE_SYSCALL(sys_unshare_4_8, int flags)
{
    enter_unshare(ctx, flags);

    return 0;
}

SEC("kretprobe/ret_sys_unshare")
int ret_sys_unshare(struct pt_regs *ctx)
{
    process_message_t pm = {0};
    exit_unshare(ctx, &pm);
    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE_SYSCALL(sys_exit, int status)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;

    // exit of a non-main thread
    if ((pid) ^ (tid))
        return 0;

    process_message_t pm = {0};
    push_exit(ctx, &pm, PM_EXIT, pid);

    return 0;
}

SEC("kprobe/sys_exit_group")
int BPF_KPROBE_SYSCALL(sys_exit_group, int status)
{
    process_message_t pm = {0};
    push_exit(ctx, &pm, PM_EXITGROUP, bpf_get_current_pid_tgid() >> 32);

    return 0;
}

SEC("kprobe/sys_execveat")
int BPF_KPROBE_SYSCALL(sys_execveat,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_delete_elem(&scripts, &pid);

    return 0;
}

SEC("kprobe/sys_execve")
int BPF_KPROBE_SYSCALL(sys_execve,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_delete_elem(&scripts, &pid);

    return 0;
}

SEC("kprobe/load_script")
int load_script(struct pt_regs *ctx)
{
    void *bprm = (void *)PT_REGS_PARM1(ctx);
    enter_script(ctx, bprm);

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
