#include "vmlinux.h"

#include "common/bpf_helpers.h"
#include "common/definitions.h"
#include "common/types.h"

#define DECLARE_EVENT(TYPE, SP)                \
    u64 pid_tgid = bpf_get_current_pid_tgid(); \
    u32 pid = pid_tgid >> 32;                  \
    u32 tid = pid_tgid & 0xFFFFFFFF;           \
    u64 mono_ns = bpf_ktime_get_ns();          \
    TYPE ev = {                                \
        .syscall_pattern = SP,                 \
        .pid = pid,                            \
        .tid = tid,                            \
        .mono_ns = mono_ns,                    \
    }

typedef struct
{
    void *iov_base; /* Starting address */
    size_t iov_len; /* Number of bytes to transfer */
} iovec_t, *piovec_t;

/*
***** MAPS
*/
struct bpf_map_def SEC("maps/wpm_events") write_process_memory_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let loader set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tp_events") trace_process_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let loader set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

static __always_inline syscall_pattern_type_t ptrace_syscall_pattern(u32 request)
{
    switch (request)
    {
    case PTRACE_POKETEXT:
        return SP_PTRACE_POKETEXT;
    case PTRACE_POKEDATA:
        return SP_PTRACE_POKEDATA;
#ifdef __aarch64__
    case COMPAT_PTRACE_SETREGS:
        return SP_PTRACE_SETREGS;
    case COMPAT_PTRACE_SET_SYSCALL:
        return SP_PTRACE_SET_SYSCALL;
    case COMPAT_PTRACE_SETVFPREGS:
        return SP_PTRACE_SETREGS;
    case COMPAT_PTRACE_SETHBPREGS:
        return SP_PTRACE_SETREGS;
#else
    case PTRACE_SETREGS:
        return SP_PTRACE_SETREGS;
#endif
    case PTRACE_SETREGSET:
        return SP_PTRACE_SETREGSET;
    case PTRACE_POKEUSR:
        return SP_PTRACE_POKEUSR;
    case PTRACE_ATTACH:
        return SP_PTRACE_ATTACH;
    case PTRACE_SEIZE:
        return SP_PTRACE_SEIZE;
    }

    return SP_IGNORE;
}

SEC("kprobe/sys_ptrace_write")
int BPF_KPROBE_SYSCALL(sys_ptrace_write,
                       u32 request, u32 target_pid, void *addr)
{
    syscall_pattern_type_t syscall_pattern = ptrace_syscall_pattern(request);
    if (SP_IGNORE == syscall_pattern)
    {
        goto Exit;
    }

    if (SP_PTRACE_ATTACH != syscall_pattern && SP_PTRACE_SEIZE != syscall_pattern)
    {
        DECLARE_EVENT(write_process_memory_event_t, syscall_pattern);
        ev.target_pid = target_pid;
        ev.addresses[0] = (u64)addr;

        bpf_perf_event_output(ctx,
                              &write_process_memory_events,
                              BPF_F_CURRENT_CPU,
                              &ev,
                              sizeof(ev));
    }

Exit:
    return 0;
}

SEC("kprobe/sys_ptrace")
int BPF_KPROBE_SYSCALL(sys_ptrace,
                       u32 request, u32 target_pid)
{
    syscall_pattern_type_t syscall_pattern = ptrace_syscall_pattern(request);
    if (SP_IGNORE == syscall_pattern)
    {
        goto Exit;
    }

    if (SP_PTRACE_ATTACH == syscall_pattern || SP_PTRACE_SEIZE == syscall_pattern)
    {
        DECLARE_EVENT(trace_process_event_t, syscall_pattern);
        ev.target_pid = target_pid;

        bpf_perf_event_output(ctx,
                              &trace_process_events,
                              BPF_F_CURRENT_CPU,
                              &ev,
                              sizeof(ev));
    }

Exit:
    return 0;
}

struct syscalls_enter_process_vm_writev_args {
    __u64 unused;
    long __syscall_nr;
    unsigned long pid;
    const struct iovec *lvec;
    unsigned long liovcnt;
    const struct iovec *rvec;
    unsigned long riovcnt;
    unsigned long flags;
};

SEC("kprobe/sys_process_vm_writev")
int BPF_KPROBE_SYSCALL(sys_process_vm_writev,
                       u32 target_pid, const struct iovec *liov, u32 liovcnt, const struct iovec *riov, u32 riovcnt)
{
    DECLARE_EVENT(write_process_memory_event_t, SP_PROCESS_VM_WRITEV);
    ev.target_pid = target_pid;

#pragma unroll MAX_ADDRESSES
    for (u32 ii = 0; ii < MAX_ADDRESSES && ii < riovcnt; ++ii)
        {
            iovec_t remote_iov;
            bpf_probe_read_user(&remote_iov, sizeof(remote_iov), &riov[ii]);
            ev.addresses[ii] = (u64)remote_iov.iov_base;
        }

    bpf_perf_event_output(ctx, &write_process_memory_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
