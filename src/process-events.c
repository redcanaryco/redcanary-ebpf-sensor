// SPDX-License-Identifier: GPL-2.0+

#include "vmlinux.h"

#include "common/bpf_helpers.h"
#include "common/types.h"

#include "process/clone.h"
#include "process/exec.h"
#include "process/exit.h"
#include "process/unshare.h"

SEC("tracepoint/sys_exec_pwd")
int sys_exec_pwd(void *ctx)
{
    process_pwd(ctx);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_execve(struct syscalls_exit_args *ctx)
{
    exit_exec(ctx, PM_EXECVE, bpf_get_current_cgroup_id(), RET_SYS_EXECVE);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int sys_exit_execveat(struct syscalls_exit_args *ctx)
{
    exit_exec(ctx, PM_EXECVEAT, bpf_get_current_cgroup_id(), RET_SYS_EXECVEAT);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve_pre_4_18")
int sys_exit_execve_pre_4_18(struct syscalls_exit_args *ctx)
{
    exit_exec(ctx, PM_EXECVE, 0, RET_SYS_EXECVE);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat_pre_4_18")
int sys_exit_execveat_pre_4_18(struct syscalls_exit_args *ctx)
{
    exit_exec(ctx, PM_EXECVEAT, 0, RET_SYS_EXECVEAT);

    return 0;
}

struct syscalls_enter_clone_args {
    __u64 unused;
    long __syscall_nr;
    unsigned long clone_flags;
    unsigned long newsp;
    int *parent_tid;
    #if defined(__TARGET_ARCH_x86)
    int *child_tid;
    unsigned long tls;
    #elif defined(__TARGET_ARCH_arm64)
    unsigned long tls;
    int *child_tid;
    #endif
};

SEC("tracepoint/syscalls/sys_enter_clone")
int sys_enter_clone(struct syscalls_enter_clone_args *args) {
    enter_clone(args, PM_CLONE, args->clone_flags);
    return 0;
}

struct syscalls_enter_clone3_args {
    __u64 unused;
    long __syscall_nr;
    struct clone_args *uargs;
    size_t size;
};

SEC("tracepoint/syscalls/sys_enter_clone3")
int sys_enter_clone3(struct syscalls_enter_clone3_args *args)
{
    u64 flags = 0;
    bpf_probe_read_user(&flags, sizeof(u64), &args->uargs->flags);

    enter_clone(args, PM_CLONE3, flags);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int sys_exit_clone3(struct syscalls_exit_args *ctx)
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

SEC("tracepoint/syscalls/sys_enter_fork")
int sys_enter_fork(void *ctx)
{
    enter_clone(ctx, PM_FORK, SIGCHLD);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int sys_enter_vfork(void *ctx)
{
    enter_clone(ctx, PM_VFORK, CLONE_VFORK | CLONE_VM | SIGCHLD);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int sys_exit_clone(struct syscalls_exit_args *ctx)
{
    process_message_t pm = {0};
    exit_clone(ctx, &pm, PM_CLONE);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fork")
int sys_exit_fork(struct syscalls_exit_args *ctx)
{
    process_message_t pm = {0};
    exit_clone(ctx, &pm, PM_FORK);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int sys_exit_vfork(struct syscalls_exit_args *ctx)
{
    process_message_t pm = {0};
    exit_clone(ctx, &pm, PM_VFORK);
    return 0;
}

struct syscalls_enter_unshare_args {
    __u64 unused;
    long __syscall_nr;
    unsigned long unshare_flags;
};

SEC("tracepoint/syscalls/sys_enter_unshare")
int sys_enter_unshare(struct syscalls_enter_unshare_args *args)
{
    enter_unshare(args, args->unshare_flags);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unshare")
int sys_exit_unshare(struct syscalls_exit_args *ctx)
{
    process_message_t pm = {0};
    exit_unshare(ctx, &pm);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int sys_enter_exit(void *ctx)
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

SEC("tracepoint/syscalls/sys_enter_exit_group")
int sys_enter_exit_group(void *ctx)
{
    process_message_t pm = {0};
    push_exit(ctx, &pm, PM_EXITGROUP, bpf_get_current_pid_tgid() >> 32);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(void *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_delete_elem(&scripts, &pid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(void *ctx)
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
