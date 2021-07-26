// SPDX-License-Identifier: GPL-2.0+

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/uio.h>
#include <linux/fcntl.h>

#include "bpf_helpers.h"
#include "types.h"
#include "offsets.h"

#define MAX_TELEMETRY_STACK_ENTRIES 128
#define CLONE_ARGS_SIZE_VER0 64 /* sizeof first published struct */
#define CLONE_ARGS_SIZE_VER1 80 /* sizeof second published struct */
#define CLONE_ARGS_SIZE_VER2 88 /* sizeof third published struct */

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
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/cpm_events") change_process_memory_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tp_events") trace_process_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/mount_events") mount_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/cred_hash") cred_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(credentials_event_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/cred_events") cred_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/pam_hash") pam_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(pam_event_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/pam_events") pam_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/rrs_events") rrs_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

/*
    Telemetry may have multiple events associated with an single
    syscall.
*/
struct bpf_map_def SEC("maps/telemetry_stack") telemetry_stack = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(telemetry_event_t),
    .max_entries = MAX_TELEMETRY_STACK_ENTRIES,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/telemetry_index") telemetry_index = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/read_flush_index") read_flush_index = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 1,
        .pinning = 0,
        .namespace = "",
};

struct bpf_map_def SEC("maps/clone_info_store") clone_info_store = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(clone_info_t),
        .max_entries = 1,
        .pinning = 0,
        .namespace = "",
};

struct bpf_map_def SEC("maps/clone3_info_store") clone3_info_store = {
        .type = BPF_MAP_TYPE_PERCPU_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(clone3_info_t),
        .max_entries = 1,
        .pinning = 0,
        .namespace = "",
};

struct bpf_map_def SEC("maps/telemetry_events") telemetry_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024 * 16,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/telemetry_ids") telemetry_ids = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tail_call_table") tail_call_table  = {
        .type = BPF_MAP_TYPE_PROG_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 32,
        .pinning = 0,
        .namespace = "",
};

struct bpf_map_def SEC("maps/offsets") offsets = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u64),
        .value_size = sizeof(u32),
        .max_entries = 4096,
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

#define DECLARE_CRED_EVENT(SP)                 \
    u64 pid_tgid = bpf_get_current_pid_tgid(); \
    u32 pid = pid_tgid >> 32;                  \
    u32 tid = pid_tgid & 0xFFFFFFFF;           \
    u64 ruid_rgid = bpf_get_current_uid_gid(); \
    u32 __rgid = ruid_rgid >> 32;              \
    u32 __ruid = ruid_rgid & 0xFFFFFFFF;       \
    u64 mono_ns = bpf_ktime_get_ns();          \
    credentials_event_t ev = {                 \
        .syscall_pattern = SP,                 \
        .pid = pid,                            \
        .tid = tid,                            \
        .current_ruid = __ruid,                \
        .current_rgid = __rgid,                \
        .euid = -1,                            \
        .egid = -1,                            \
        .ruid = -1,                            \
        .rgid = -1,                            \
        .suid = -1,                            \
        .sgid = -1,                            \
        .mono_ns = mono_ns,                    \
    }

#define DECLARE_PAM_EVENT(STAGE)               \
    u64 pid_tgid = bpf_get_current_pid_tgid(); \
    u32 pid = pid_tgid >> 32;                  \
    u32 tid = pid_tgid & 0xFFFFFFFF;           \
    u64 mono_ns = bpf_ktime_get_ns();          \
    pam_event_t ev = {                         \
        .syscall_pattern = SP_USERMODE,        \
        .pid = pid,                            \
        .tid = tid,                            \
        .stage = STAGE,                        \
        .mono_ns = mono_ns,                    \
    }

#define FILL_TELEMETRY_SYSCALL_EVENT(E, SP)                                         \
    u64 pid_tgid = bpf_get_current_pid_tgid();                                      \
    E->done = FALSE;                                                                \
    E->telemetry_type = TE_SYSCALL_INFO;                                            \
    E->u.syscall_info.pid = pid_tgid >> 32;                                         \
    E->u.syscall_info.tid = pid_tgid & 0xFFFFFFFF;                                  \
    E->u.syscall_info.ppid = -1;                                                    \
    E->u.syscall_info.luid = -1;                                                    \
    E->u.syscall_info.euid = bpf_get_current_uid_gid() >> 32;                       \
    E->u.syscall_info.egid = bpf_get_current_uid_gid() & 0xFFFFFFFF;                \
    E->u.syscall_info.mono_ns = bpf_ktime_get_ns();                                 \
    E->u.syscall_info.syscall_pattern = SP;                                         \
    bpf_get_current_comm(E->u.syscall_info.comm, sizeof(E->u.syscall_info.comm));

#define FILL_TELEMETRY_SYSCALL_RET(E, SP) \


#define GET_OFFSETS_4_8 \
    /* if "loaded" doesn't exist in the map, we get NULL back and won't read from offsets                           \
     * when offsets are loaded into the offsets map, "loaded" should be given any value                             \
     */                                                                                                             \
    u64 loaded = CRC_LOADED;                                                         \
    loaded = (u64) bpf_map_lookup_elem(&offsets, &loaded); /* squeezing out as much stack as possible */            \
    /* since we're using offsets to read from the structs, we don't need to bother with                             \
     * understanding their structure                                                                                \
     */                                                                                                             \
    void *ts = (void *)bpf_get_current_task();                                                                      \
    void *pts = NULL;                                                                                               \
    if (ts && loaded) {                                                                                             \
        u64 real_parent_offset = CRC_TASK_STRUCT_REAL_PARENT;                                                       \
        u64 ppid_offset = CRC_TASK_STRUCT_PID;                                                                      \
        u64 luid_offset = CRC_TASK_STRUCT_LOGINUID;                                                                 \
        real_parent_offset = (u64) bpf_map_lookup_elem(&offsets, &real_parent_offset);                              \
        ppid_offset = (u64) bpf_map_lookup_elem(&offsets, &ppid_offset);                                            \
        luid_offset = (u64) bpf_map_lookup_elem(&offsets, &luid_offset);                                            \
        if (real_parent_offset && ppid_offset && luid_offset)                                                       \
        {                                                                                                           \
            bpf_probe_read(&pts, sizeof(pts), ts + *(u32*)real_parent_offset);                                      \
            if (pts)                                                                                                \
            {                                                                                                       \
                bpf_probe_read(&ppid, sizeof(ppid), pts + *(u32*)ppid_offset);                                      \
            }                                                                                                       \
            bpf_probe_read(&luid, sizeof(luid), ts + *(u32*)luid_offset);                                           \
        }                                                                                                           \
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
                              bpf_get_smp_processor_id(),
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
                              bpf_get_smp_processor_id(),
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

#pragma unroll
    for (u32 ii = 0; ii < MAX_ADDRESSES && ii < riovcnt; ++ii, riov++)
    {
        iovec_t remote_iov;
        bpf_probe_read_user(&remote_iov, sizeof(remote_iov), (const void *)riov);
        ev.addresses[ii] = (u64)remote_iov.iov_base;
    }

    bpf_perf_event_output(ctx,
                          &write_process_memory_events,
                          bpf_get_smp_processor_id(),
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
                          bpf_get_smp_processor_id(),
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
                          bpf_get_smp_processor_id(),
                          &ev,
                          sizeof(ev));

    return 0;
}

SEC("kprobe/do_mount")
int kprobe__do_mount(struct pt_regs *ctx)
{
    DECLARE_EVENT(mount_event_t, SP_MOUNT);

    bpf_probe_read_str(&ev.source, sizeof(ev.source), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read_str(&ev.target, sizeof(ev.target), (void *)PT_REGS_PARM2(ctx));
    bpf_probe_read_str(&ev.fs_type, sizeof(ev.fs_type), (void *)PT_REGS_PARM3(ctx));
    ev.flags = PT_REGS_PARM4(ctx);
    bpf_probe_read_str(&ev.data, sizeof(ev.data), (void *)PT_REGS_PARM5(ctx));

    bpf_perf_event_output(ctx,
                          &mount_events,
                          bpf_get_smp_processor_id(),
                          &ev,
                          sizeof(ev));

    return 0;
}

static __always_inline int dispatch_credentials_event(struct pt_regs *__ctx)
{
    struct pt_regs ctx = {};
    bpf_probe_read(&ctx, sizeof(ctx), (void *)SYSCALL_PARM1(__ctx));
    u64 pid_tgid = bpf_get_current_pid_tgid();

    credentials_event_t *pcreds = bpf_map_lookup_elem(&cred_hash, &pid_tgid);
    if (NULL == pcreds)
    {
        goto Exit;
    }

    if (0 == PT_REGS_RC(&ctx))
    {
        bpf_perf_event_output(__ctx,
                              &cred_events,
                              bpf_get_smp_processor_id(),
                              pcreds,
                              sizeof(*pcreds));
    }

    bpf_map_delete_elem(&cred_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("kprobe/sys_setuid")
int BPF_KPROBE_SYSCALL(kprobe__sys_setuid,
                       u32 ruid)
{
    DECLARE_CRED_EVENT(SP_SETUID);
    ev.ruid = ruid;
    bpf_map_update_elem(&cred_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_setuid")
int kretprobe__sys_setuid(struct pt_regs *__ctx)
{
    return dispatch_credentials_event(__ctx);
}

SEC("kprobe/sys_setgid")
int BPF_KPROBE_SYSCALL(kprobe__sys_setgid,
                       u32 rgid)
{
    DECLARE_CRED_EVENT(SP_SETGID);
    ev.rgid = rgid;
    bpf_map_update_elem(&cred_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_setgid")
int kretprobe__sys_setgid(struct pt_regs *__ctx)
{
    return dispatch_credentials_event(__ctx);
}

SEC("kprobe/sys_setreuid")
int BPF_KPROBE_SYSCALL(kprobe__sys_setreuid,
                       u32 ruid, u32 euid)
{
    DECLARE_CRED_EVENT(SP_SETREUID);
    ev.ruid = ruid;
    ev.euid = euid;
    bpf_map_update_elem(&cred_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_setreuid")
int kretprobe__sys_setreuid(struct pt_regs *__ctx)
{
    return dispatch_credentials_event(__ctx);
}

SEC("kprobe/sys_setregid")
int BPF_KPROBE_SYSCALL(kprobe__sys_setregid,
                       u32 rgid, u32 egid)
{
    DECLARE_CRED_EVENT(SP_SETREGID);
    ev.rgid = rgid;
    ev.egid = egid;
    bpf_map_update_elem(&cred_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_setregid")
int kretprobe__sys_setregid(struct pt_regs *__ctx)
{
    return dispatch_credentials_event(__ctx);
}

SEC("kprobe/sys_setresuid")
int BPF_KPROBE_SYSCALL(kprobe__sys_setresuid,
                       u32 ruid, u32 euid, u32 suid)
{
    DECLARE_CRED_EVENT(SP_SETREUID);
    ev.ruid = ruid;
    ev.euid = euid;
    ev.suid = suid;
    bpf_map_update_elem(&cred_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_setresuid")
int kretprobe__sys_setresuid(struct pt_regs *__ctx)
{
    return dispatch_credentials_event(__ctx);
}

SEC("kprobe/sys_setresgid")
int BPF_KPROBE_SYSCALL(kprobe__sys_setresgid,
                       u32 rgid, u32 egid, u32 sgid)
{
    DECLARE_CRED_EVENT(SP_SETREGID);
    ev.rgid = rgid;
    ev.egid = egid;
    ev.sgid = sgid;
    bpf_map_update_elem(&cred_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("kretprobe/sys_setresgid")
int kretprobe__sys_setresgid(struct pt_regs *__ctx)
{
    return dispatch_credentials_event(__ctx);
}

SEC("uprobe/pam_start")
int uprobe__pam_start(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_START);
    bpf_probe_read(ev.u.pam_start.service_name, sizeof(ev.u.pam_start.user_name), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(ev.u.pam_start.service_name, sizeof(ev.u.pam_start.user_name), (void *)PT_REGS_PARM2(ctx));
    ev.pam_handle = (u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_start")
int uretprobe__pam_start(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    if (0 == PT_REGS_RC(ctx))
    {
        bpf_probe_read(&ppam->pam_handle, sizeof(ppam->pam_handle), (void *)ppam->pam_handle);

        bpf_perf_event_output(ctx,
                              &pam_events,
                              bpf_get_smp_processor_id(),
                              ppam,
                              sizeof(*ppam));
    }

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_end")
int uprobe__pam_end(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_END);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          bpf_get_smp_processor_id(),
                          &ev,
                          sizeof(ev));
    return 0;
}

SEC("uprobe/pam_authenticate")
int uprobe__pam_authenticate(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_AUTHENTICATE);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.flags = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_authenticate")
int uretprobe__pam_authenticate(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          bpf_get_smp_processor_id(),
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_chauthtok")
int uprobe__pam_chauthtok(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_CHAUTHTOK);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.flags = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_chauthtok")
int uretprobe__pam_chauthtok(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          bpf_get_smp_processor_id(),
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_set_item")
int uprobe__pam_set_item(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_SET_ITEM);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.u.pam_set_item.item_type = (pam_item_type_t)PT_REGS_PARM2(ctx);
    bpf_probe_read(ev.u.pam_set_item.data, sizeof(ev.u.pam_set_item.data), (void *)PT_REGS_PARM3(ctx));
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_set_item")
int uretprobe__pam_set_item(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          bpf_get_smp_processor_id(),
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_setcred")
int uprobe__pam_setcred(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_SET_CRED);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.flags = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_setcred")
int uretprobe__pam_setcred(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          bpf_get_smp_processor_id(),
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/read_return_string")
int uprobe__read_return_string(struct pt_regs *ctx)
{
    DECLARE_EVENT(read_return_string_event_t, SP_USERMODE);
    bpf_probe_read(ev.value, sizeof(ev.value), (void *)PT_REGS_RC(ctx));
    bpf_perf_event_output(ctx,
                          &rrs_events,
                          bpf_get_smp_processor_id(),
                          &ev,
                          sizeof(ev));
    return 0;
}

static __always_inline void clear_telemetry_events()
{
    // The key is always zero since the index is just a simple state counter
    u32 key = 0;
    bpf_map_update_elem(&telemetry_index, &key, &key, BPF_ANY);
    bpf_map_update_elem(&read_flush_index, &key, &key, BPF_ANY);
}

static __always_inline void push_telemetry_event(ptelemetry_event_t ev)
{
    u32 key = 0;
    u32 *pcurrent_index = bpf_map_lookup_elem(&telemetry_index, &key);
    if (NULL == pcurrent_index)
    {
        return;
    }

    // setting this value directly (without the + 0) fails the verifier
    // the verifier really doesn't like this function, see the index updating below
    u32 idx = *pcurrent_index + 0;

    int ret = bpf_map_update_elem(&telemetry_stack, &idx, ev, BPF_ANY);
    if (ret < 0)
    {
        return;
    }

    // Update the index
    // this is fine:
    idx = *pcurrent_index + 1;
    // This fails verification on 4.15 with `invalid register spill`
    //      idx += 1;
    // this fails too, same message
    //      idx = idx + 1;
    ret = bpf_map_update_elem(&telemetry_index, &key, &idx, BPF_ANY);
    if (ret < 0 )
    {
        return;
    }

    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, &idx);
    if (pev)
    {
        __builtin_memcpy(ev, pev, sizeof(telemetry_event_t));
    }
    return;
}

#define FLUSH_LOOP                                                          \
    if (ii < *pcurrent_index) {                                             \
        ev = bpf_map_lookup_elem(&telemetry_stack, &ii);                    \
        ii++;                                                               \
        if (ev) {                                                           \
            bpf_perf_event_output(ctx,                                      \
                &telemetry_events,                                          \
                bpf_get_smp_processor_id(),                                 \
                ev,                                                         \
                sizeof(*ev)                                                 \
            );                                                              \
        }                                                                   \
    }

#define FLUSH_LOOP_N(N) REPEAT_##N(FLUSH_LOOP;)

static __always_inline void flush_telemetry_events(struct pt_regs *ctx)
{
    u32 key = 0;
    u32 *pcurrent_index = bpf_map_lookup_elem(&telemetry_index, &key);
    if (NULL == pcurrent_index)
    {
        return;
    }

    u32 *pii = bpf_map_lookup_elem(&read_flush_index, &key);
    if (NULL == pii)
    {
        bpf_map_update_elem(&read_flush_index, &key, &key, BPF_ANY);
        return;
    }

    // move ii to the stack for the verifier
    u32 ii = *pii;
    ptelemetry_event_t ev = NULL;

    // this number was arrived at experimentally, increasing it will result in too many
    // instructions for older kernels
    FLUSH_LOOP_N(27);

    bpf_map_update_elem(&read_flush_index, &key, &ii, BPF_ANY);
}

#define READ_LOOP(PTR, T)                                                       \
    ptr = 0;                                                                    \
    ev->u.v.truncated = FALSE;                                                  \
    ev->id = id;                                                                \
    ev->done = FALSE;                                                           \
    ev->telemetry_type = T;                                                     \
    ret = bpf_probe_read(&ptr, sizeof(u64), (void*) PTR + (ii * sizeof(u64)));  \
    if (ret < 0)                                                                \
    {                                                                           \
        goto Next;                                                              \
    }                                                                           \
    else if ((void *) ptr == NULL)                                              \
    {                                                                           \
        goto Next;                                                              \
    }                                                                           \
    else                                                                        \
    {                                                                           \
        count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *) ptr);   \
        if (count == VALUE_SIZE) {                                              \
            ev->u.v.truncated = TRUE;                                           \
        }                                                                       \
        if (count <= 0) {                                                       \
            goto Next;                                                          \
        }                                                                       \
    }                                                                           \
    push_telemetry_event(ev);                                                   \
    ii++;

#define READ_LOOP_N(PTR, T, N) REPEAT_##N(READ_LOOP(PTR, T);)

static __always_inline int enter_exec(syscall_pattern_type_t sp, int fd,
                                      const char __user *filename,
                                      const char __user *const __user *argv,
                                      const char __user *const __user *envp,
                                      int flags, struct pt_regs *ctx, u32 ppid,
                                      u32 luid)
{
    u64 id = 0; // reuse ID to save space
    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, (u32 *) &id);
    if (!pev) // this should never happen, but the verifier complains otherwise
    {
        goto Exit;
    }
    // this pointer passing and memcpy is to put the struct on the stack and satisfy the verifier
    telemetry_event_t sev = {0};
    __builtin_memcpy(&sev, pev, sizeof(telemetry_event_t));
    ptelemetry_event_t ev = &sev;

    id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    u32 pid = pid_tgid >> 32;
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ev);

    bpf_map_update_elem(&telemetry_ids, &pid, &id, BPF_ANY);


    // explicit null check to satisfy the verifier
    if (!filename)
        goto Exit;

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXE_PATH;
    ev->u.v.truncated = FALSE;
    long count = 0;
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void*) filename);
    if (count == VALUE_SIZE) {
        ev->u.v.truncated = TRUE;
    }
    push_telemetry_event(ev);


    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_TC_ARGV);


Exit:
    return 0;
}

SEC("kprobe/sys_exec_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_exec_tc_argv,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *idp = bpf_map_lookup_elem(&telemetry_ids, &pid);
    if (idp == NULL)
    {
        return 0;
    }

    u64 id = *idp;
    u64 index = 0;
    u32 *pcurrent_index = bpf_map_lookup_elem(&telemetry_index, &index);
    if (!pcurrent_index)
    {
        return 0;
    }
    u32 current_index = *pcurrent_index;
    // this needs to go on _stack_
    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, &current_index);
    if (!pev) // this should never happen, but the verifier complains otherwise
    {
        goto Exit;
    }

    // put the event on the stack and satisfy the verifier
    telemetry_event_t tev = *pev;
    ptelemetry_event_t ev = &tev;

    u32 *pii = bpf_map_lookup_elem(&read_flush_index, &index);
    if (NULL == pii)
    {
        bpf_map_update_elem(&read_flush_index, &index, &index, BPF_ANY);
        goto Tail;
    }


    long count = 0;
    u32 ii = 0;
    // explicit copy from pointer to stack, satisfy verifier
    __builtin_memcpy(&ii, pii, sizeof(u32));
    u64 ptr = 0;
    u64 ret = 0;

    // this number was arrived at experimentally, increasing it will result in too many
    // instructions for older kernels
    READ_LOOP_N(argv, TE_COMMAND_LINE, 6);

    bpf_map_update_elem(&read_flush_index, &index, &ii, BPF_ANY);

Tail:
    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_TC_ARGV);

Next:;
    u32 reset = 0;
    bpf_map_update_elem(&read_flush_index, &reset, &reset, BPF_ANY);
    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_TC_ENVP);

Exit:
    return 0;
}

SEC("kprobe/sys_exec_tc_envp")
int BPF_KPROBE_SYSCALL(kprobe__sys_exec_tc_envp,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 index = 0;
    u64 *idp = bpf_map_lookup_elem(&telemetry_ids, &pid);
    if (idp == NULL)
    {
        return 0;
    }
    u64 id = *idp;
    u32 *pcurrent_index = bpf_map_lookup_elem(&telemetry_index, &index);
    if (!pcurrent_index)
    {
        return 0;
    }
    u32 current_index = *pcurrent_index;
    // this needs to go on _stack_
    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, &current_index);
    if (!pev) // this should never happen, but the verifier complains otherwise
    {
        goto Exit;
    }

    telemetry_event_t tev = *pev;
    ptelemetry_event_t ev = &tev;

    u32 *pii = bpf_map_lookup_elem(&read_flush_index, &index);
    if (NULL == pii)
    {
        bpf_map_update_elem(&read_flush_index, &index, &index, BPF_ANY);
        goto Tail;
    }

    long count = 0;
    u32 ii = *pii;
    u64 ptr = 0;
    u64 ret = 0;

    // this number was arrived at experimentally, increasing it will result in too many
    // instructions for older kernels
    READ_LOOP_N(envp, TE_ENVIRONMENT, 6);

    bpf_map_update_elem(&read_flush_index, &index, &ii, BPF_ANY);


Tail:
    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_TC_ENVP);

Next:
Exit:;
    u32 reset = 0;
    bpf_map_update_elem(&read_flush_index, &reset, &reset, BPF_ANY);
    return 0;
}

SEC("kprobe/sys_execveat_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_4_8,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_exec(SP_EXECVEAT, fd, filename, argv, envp, flags, ctx, ppid, luid);
}


SEC("kprobe/sys_execve_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_4_8,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_exec(SP_EXECVE, AT_FDCWD, filename, argv, envp, 0, ctx, ppid, luid);
}


SEC("kprobe/sys_execveat")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    return enter_exec(SP_EXECVEAT, fd, filename, argv, envp, flags, ctx, -1, -1);
}

SEC("kprobe/sys_execve")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    return enter_exec(SP_EXECVE, AT_FDCWD, filename, argv, envp, 0, ctx, -1, -1);
}


static __always_inline int exit_exec(struct pt_regs *__ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t) {
            .id = 0,
            .done = TRUE,
            .telemetry_type = 0,
            .u.v = {
                    .value[0] = '\0',
                    .truncated = FALSE,
            },
    };
    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid);

    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(__ctx);
    push_telemetry_event(ev);

Flush:
    flush_telemetry_events(__ctx);
    bpf_tail_call(__ctx, &tail_call_table, RET_SYS_EXECVE);
    clear_telemetry_events();

    return 0;
}

SEC("kretprobe/ret_sys_execve")
int kretprobe__ret_sys_execve(struct pt_regs *ctx)
{
    return exit_exec(ctx);
}

SEC("kretprobe/ret_sys_execveat")
int kretprobe__ret_sys_execveat(struct pt_regs *ctx)
{
    return exit_exec(ctx);
}


static __always_inline int enter_clone(syscall_pattern_type_t sp, unsigned long flags,
                                       void __user *stack, int __user *parent_tid,
                                       int __user *child_tid, unsigned long tls,
                                       struct pt_regs *ctx, u32 ppid, u32 luid)
{
    u64 id = 0; // reuse ID to save space
    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, (u32 *) &id);
    if (!pev) // this should never happen, but the verifier complains otherwise
    {
        return -1;
    }

    // explicit memcpy to move the struct to the stack and satisfy the verifier
    telemetry_event_t sev = {0};
    __builtin_memcpy(&sev, pev, sizeof(telemetry_event_t));
    ptelemetry_event_t ev = &sev;

    id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    u32 pid = pid_tgid >> 32;
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ev);

    clone_info_t clone_info = {
            .flags = flags,
            .stack = (u64) stack,
            .parent_tid = -1,
            .child_tid = -1,
            .tls = tls,
            .p_ptr = (u64) parent_tid,
            .c_ptr = (u64) child_tid,
    };

    u32 key = 0;
    bpf_map_update_elem(&clone_info_store, &key, &clone_info, BPF_ANY);

    bpf_map_update_elem(&telemetry_ids, &pid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_clone(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t) {
            .id = 0,
            .done = TRUE,
            .telemetry_type = 0,
            .u.v = {
                    .value[0] = '\0',
                    .truncated = FALSE,
            },
    };

    ev->id = *id;
    ev->done = FALSE;
    ev->telemetry_type = TE_CLONE_INFO;
    u32 key = 0;
    pclone_info_t pclone_info = bpf_map_lookup_elem(&clone_info_store, &key);

    if (!pclone_info)
        goto Flush;

    clone_info_t clone_info = {
            .flags = pclone_info->flags,
            .stack = (u64) pclone_info->stack,
            .parent_tid = -1,
            .child_tid = -1,
            .tls = pclone_info->tls,
            .p_ptr = pclone_info->p_ptr,
            .c_ptr = pclone_info->c_ptr,
    };

    bpf_probe_read(&clone_info.parent_tid, sizeof(u32), (void*) pclone_info->p_ptr);
    bpf_probe_read(&clone_info.child_tid, sizeof(u32), (void*) pclone_info->c_ptr);
    ev->u.clone_info = clone_info;
    push_telemetry_event(ev);

    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid);
    ev->done = TRUE;
    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ev);


Flush:
    flush_telemetry_events(ctx);
    bpf_tail_call(ctx, &tail_call_table, RET_SYS_CLONE);
    clear_telemetry_events();

    return 0;
}


SEC("kprobe/sys_clone_4_8")
#if defined(__TARGET_ARCH_x86)
int BPF_KPROBE_SYSCALL(kprobe__sys_clone_4_8, unsigned long flags, void __user *stack,
                       int __user *parent_tid, int __user *child_tid, unsigned long tls)
#elif defined(__TARGET_ARCH_arm64)
int BPF_KPROBE_SYSCALL(kprobe__sys_clone_4_8, unsigned long flags, void __user *stack,
                       int __user *parent_tid, unsigned long tls, int __user *child_tid)
#endif
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_clone(SP_CLONE, flags, stack, parent_tid, child_tid, tls, ctx, ppid, luid);
}


SEC("kprobe/sys_clone")
#if defined(__TARGET_ARCH_x86)
int BPF_KPROBE_SYSCALL(kprobe__sys_clone, unsigned long flags, void *stack,
                       int *parent_tid, int *child_tid, unsigned long tls)
#elif defined(__TARGET_ARCH_arm64)
int BPF_KPROBE_SYSCALL(kprobe__sys_clone, unsigned long flags, void *stack,
                       int *parent_tid, unsigned long tls, int *child_tid)
#endif
{
    return enter_clone(SP_CLONE, flags, stack, parent_tid, child_tid, tls, ctx, -1, -1);
}


static __always_inline int enter_clone3(syscall_pattern_type_t sp, struct clone_args __user *uargs,
                                        size_t size, struct pt_regs *ctx, u32 ppid, u32 luid)
{
    u64 id = 0; // reuse ID to save space
    ptelemetry_event_t ev = bpf_map_lookup_elem(&telemetry_stack, (u32 *) &id);
    if (!ev) // this should never happen, but the verifier complains otherwise
    {
        return -1;
    }
    telemetry_event_t sev = {0};
    __builtin_memcpy(&sev, ev, sizeof(telemetry_event_t));
    ev = &sev;

    id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);

    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ev);
    pid_tgid = pid_tgid >> 32;
    bpf_map_update_elem(&telemetry_ids, (u32 *)&pid_tgid, &id, BPF_ANY);

    clone3_info_t clone3_info = {0};
    clone3_info.size = (u64) size;

    bpf_probe_read(&clone3_info.flags, sizeof(u64), &uargs->flags);
    bpf_probe_read(&clone3_info.c_ptr, sizeof(u64), &uargs->child_tid);
    bpf_probe_read(&clone3_info.p_ptr, sizeof(u64), &uargs->parent_tid);
    bpf_probe_read(&clone3_info.stack, sizeof(u64), &uargs->stack);
    bpf_probe_read(&clone3_info.tls, sizeof(u64), &uargs->tls);
    if (size >= CLONE_ARGS_SIZE_VER1)
    {
        bpf_probe_read(&clone3_info.set_tid, sizeof(u64), &uargs->set_tid);
        bpf_probe_read(&clone3_info.set_tid_size, sizeof(u64), &uargs->set_tid_size);
    }
    if (size >= CLONE_ARGS_SIZE_VER2)
    {
        bpf_probe_read(&clone3_info.cgroup, sizeof(u64), &uargs->cgroup);
    }

    id = 0;
    bpf_map_update_elem(&clone3_info_store, &id, &clone3_info, BPF_ANY);

    return 0;
}

static __always_inline int exit_clone3(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t) {
            .id = 0,
            .done = TRUE,
            .telemetry_type = 0,
            .u.v = {
                    .value[0] = '\0',
                    .truncated = FALSE,
            },
    };

    ev->id = *id;
    ev->done = FALSE;
    ev->telemetry_type = TE_CLONE3_INFO;
    u32 key = 0;
    pclone3_info_t pclone3_info = bpf_map_lookup_elem(&clone3_info_store, &key);

    if (!pclone3_info)
        goto Flush;

    clone3_info_t clone_info = {0};

    clone_info.flags = pclone3_info->flags;
    clone_info.stack = (u64) pclone3_info->stack;
    clone_info.parent_tid = -1;
    clone_info.child_tid = -1;
    clone_info.tls = pclone3_info->tls;
    clone_info.size = pclone3_info->size;
    clone_info.p_ptr = pclone3_info->p_ptr;
    clone_info.c_ptr = pclone3_info->c_ptr;
    if (pclone3_info->size >= CLONE_ARGS_SIZE_VER1)
    {
        clone_info.set_tid = pclone3_info->set_tid;
        clone_info.set_tid_size = pclone3_info->set_tid_size;
    }
    if (pclone3_info->size >= CLONE_ARGS_SIZE_VER2)
    {
        clone_info.cgroup = pclone3_info->cgroup;
    }

    bpf_probe_read(&clone_info.parent_tid, sizeof(u32), (void*) clone_info.p_ptr);
    bpf_probe_read(&clone_info.child_tid, sizeof(u32), (void*) clone_info.c_ptr);
    ev->u.clone3_info = clone_info;
    push_telemetry_event(ev);

    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid);
    ev->done = TRUE;
    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ev);

Flush:
    flush_telemetry_events(ctx);
    bpf_tail_call(ctx, &tail_call_table, RET_SYS_CLONE3);
    clear_telemetry_events();

    return 0;
}

SEC("kprobe/sys_clone3")
int BPF_KPROBE_SYSCALL(kprobe__sys_clone3, struct clone_args __user *uargs, size_t size)
{
    // clone3 was added in 5.3, so this should always be available if clone3 is attachable
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_clone3(SP_CLONE3, uargs, size, ctx, ppid, luid);
}

SEC("kretprobe/ret_sys_clone3")
int kretprobe__ret_sys_clone3(struct pt_regs *ctx)
{
    return exit_clone3(ctx);
}


SEC("kprobe/sys_fork")
int BPF_KPROBE_SYSCALL(kprobe__sys_fork)
{
    return enter_clone(SP_FORK, 0, NULL, NULL, NULL, 0, ctx, -1, -1);
}

SEC("kprobe/sys_vfork")
int BPF_KPROBE_SYSCALL(kprobe__sys_vfork)
{
    return enter_clone(SP_VFORK, 0, NULL, NULL, NULL, 0, ctx, -1, -1);
}

SEC("kprobe/sys_fork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_fork_4_8)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_clone(SP_FORK, 0, NULL, NULL, NULL, 0, ctx, ppid, luid);
}

SEC("kprobe/sys_vfork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_vfork_4_8)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_clone(SP_VFORK, 0, NULL, NULL, NULL, 0, ctx, ppid, luid);
}

SEC("kretprobe/ret_sys_clone")
int kretprobe__ret_sys_clone(struct pt_regs *ctx)
{
    return exit_clone(ctx);
}

SEC("kretprobe/ret_sys_fork")
int kretprobe__ret_sys_fork(struct pt_regs *ctx)
{
    return exit_clone(ctx);
}

SEC("kretprobe/ret_sys_vfork")
int kretprobe__ret_sys_vfork(struct pt_regs *ctx)
{
    return exit_clone(ctx);
}

static __always_inline int enter_unshare(syscall_pattern_type_t sp, int flags,
                                         struct pt_regs *ctx, u32 ppid, u32 luid)
{
    u64 id = 0; // reuse ID to save space
    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, (u32 *) &id);
    if (!pev) // this should never happen, but the verifier complains otherwise
    {
        return -1;
    }
    telemetry_event_t sev = {0};
    __builtin_memcpy(&sev, pev, sizeof(telemetry_event_t));
    ptelemetry_event_t ev = &sev;

    id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    u32 pid = pid_tgid >> 32;
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_UNSHARE_FLAGS;
    ev->u.unshare_flags = flags;
    push_telemetry_event(ev);

    bpf_map_update_elem(&telemetry_ids, &pid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_unshare(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t) {
            .id = 0,
            .done = TRUE,
            .telemetry_type = 0,
            .u.v = {
                    .value[0] = '\0',
                    .truncated = FALSE,
            },
    };
    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid);

    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ev);

Flush:
    flush_telemetry_events(ctx);
    bpf_tail_call(ctx, &tail_call_table, RET_SYS_UNSHARE);
    clear_telemetry_events();

    return 0;
}

SEC("kprobe/sys_unshare_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_unshare_4_8, int flags)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_unshare(SP_UNSHARE, flags, ctx, ppid, luid);
}

SEC("kprobe/sys_unshare")
int BPF_KPROBE_SYSCALL(kprobe__sys_unshare, int flags)
{
    return enter_unshare(SP_UNSHARE, flags, ctx, -1, -1);
}

SEC("kretprobe/ret_sys_unshare")
int kretprobe__ret_sys_unshare(struct pt_regs *ctx)
{
    return exit_unshare(ctx);
}


static __always_inline int enter_exit(syscall_pattern_type_t sp, int status,
                                         struct pt_regs *ctx, u32 ppid, u32 luid)
{
    u64 id = 0; // reuse ID to save space
    ptelemetry_event_t pev = bpf_map_lookup_elem(&telemetry_stack, (u32 *) &id);
    if (!pev) // this should never happen, but the verifier complains otherwise
    {
        return -1;
    }

    // explicit memcpy to put the struct on the stack and satisfy the verifier
    telemetry_event_t sev = {0};
    __builtin_memcpy(&sev, pev, sizeof(telemetry_event_t));
    ptelemetry_event_t ev = &sev;


    id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    u32 pid = pid_tgid >> 32;
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXIT_STATUS;
    ev->u.exit_status = status;
    push_telemetry_event(ev);
    bpf_map_update_elem(&telemetry_ids, &pid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_exit(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t) {
            .id = 0,
            .done = TRUE,
            .telemetry_type = 0,
            .u.v = {
                    .value[0] = '\0',
                    .truncated = FALSE,
            },
    };
    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid);

    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ev);

Flush:
    flush_telemetry_events(ctx);
    bpf_tail_call(ctx, &tail_call_table, 6);

    clear_telemetry_events();

    return 0;
}

SEC("kprobe/sys_exit_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_4_8, int status)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_exit(SP_EXIT, status, ctx, ppid, luid);
}

SEC("kprobe/sys_exit")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit, int status)
{
    return enter_exit(SP_EXIT, status, ctx, -1, -1);
}

SEC("kprobe/sys_exit_group_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_group_4_8, int status)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    return enter_exit(SP_EXITGROUP, status, ctx, ppid, luid);
}

SEC("kprobe/sys_exit_group")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_group, int status)
{
    return enter_exit(SP_EXITGROUP, status, ctx, -1, -1);
}

SEC("kretprobe/ret_sys_exit")
int kretprobe__ret_sys_exit(struct pt_regs *ctx)
{
    return exit_exit(ctx);
}

SEC("kretprobe/ret_sys_exit_group")
int kretprobe__ret_sys_exit_group(struct pt_regs *ctx)
{
    return exit_exit(ctx);
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
