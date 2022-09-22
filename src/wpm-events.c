#include <linux/kconfig.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/uio.h>
#include <linux/fcntl.h>
#include "bpf_helpers.h"
#include "types.h"
#include "offsets.h"
#include "repeat.h"
#include "common.h"

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
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/cpm_events") change_process_memory_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tp_events") trace_process_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/rrs_events") rrs_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
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

SEC("uprobe/read_return_string")
int uprobe__read_return_string(struct pt_regs *ctx)
{
    DECLARE_EVENT(read_return_string_event_t, SP_USERMODE);
    bpf_probe_read(ev.value, sizeof(ev.value), (void *)PT_REGS_RC(ctx));
    bpf_perf_event_output(ctx,
                          &rrs_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));
    return 0;
}

SEC("kprobe/sys_ptrace_write")
int BPF_KPROBE_SYSCALL(kprobe__sys_ptrace_write,
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
int BPF_KPROBE_SYSCALL(kprobe__sys_ptrace,
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

SEC("kprobe/sys_process_vm_writev_5_5")
int BPF_KPROBE_SYSCALL(kprobe__sys_process_vm_writev_5_5,
                       u32 target_pid, piovec_t liov, u32 liovcnt, piovec_t riov, u32 riovcnt)
{
    DECLARE_EVENT(write_process_memory_event_t, SP_PROCESS_VM_WRITEV);
    ev.target_pid = target_pid;

#pragma unroll MAX_ADDRESSES
    for (u32 ii = 0; ii < MAX_ADDRESSES && ii < riovcnt; ++ii, riov++)
    {
        iovec_t remote_iov;
        bpf_probe_read_user(&remote_iov, sizeof(remote_iov), (const void *)riov);
        ev.addresses[ii] = (u64)remote_iov.iov_base;
    }

    bpf_perf_event_output(ctx,
                          &write_process_memory_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_process_vm_writev")
int BPF_KPROBE_SYSCALL(kprobe__sys_process_vm_writev,
                       u32 target_pid)
{
    DECLARE_EVENT(write_process_memory_event_t, SP_PROCESS_VM_WRITEV);
    ev.target_pid = target_pid;

    bpf_perf_event_output(ctx,
                          &write_process_memory_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/sys_mprotect")
int BPF_KPROBE_SYSCALL(kprobe__sys_mprotect,
                       void *addr, u64 len, u32 prot)
{
    DECLARE_EVENT(change_memory_permission_event_t, SP_MPROTECT);
    ev.address = (u64)addr;
    ev.len = len;
    ev.prot = prot;

    bpf_perf_event_output(ctx,
                          &change_process_memory_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
