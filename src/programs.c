// SPDX-License-Identifier: GPL-2.0+

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <linux/uio.h>
#include <linux/fcntl.h>
#include "bpf_helpers.h"
#include "types.h"
#include "offsets.h"
#include "repeat.h"

#define MAX_TELEMETRY_STACK_ENTRIES 1024
#define CLONE_ARGS_SIZE_VER0 64 /* sizeof first published struct */
#define CLONE_ARGS_SIZE_VER1 80 /* sizeof second published struct */
#define CLONE_ARGS_SIZE_VER2 88 /* sizeof third published struct */

// Just doing a simple 16-bit byte swap
#define SWAP_U16(x) (((x) >> 8) | ((x) << 8))

typedef struct
{
    void *iov_base; /* Starting address */
    size_t iov_len; /* Number of bytes to transfer */
} iovec_t, *piovec_t;

typedef void *_skbuff;
typedef void *_sock;

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
    .max_entries = MAX_TELEMETRY_STACK_ENTRIES * 64,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcpv4_connect") tcpv4_connect = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udpv4_sendmsg_map") udpv4_sendmsg_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcpv6_connect") tcpv6_connect = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/telemetry_ids") telemetry_ids = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udpv6_sendmsg_map") udpv6_sendmsg_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tail_call_table") tail_call_table = {
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

#define FILL_TELEMETRY_SYSCALL_EVENT(E, SP)                          \
    u64 pid_tgid = bpf_get_current_pid_tgid();                       \
    E->done = FALSE;                                                 \
    E->telemetry_type = TE_SYSCALL_INFO;                             \
    E->u.syscall_info.pid = pid_tgid >> 32;                          \
    E->u.syscall_info.tid = pid_tgid & 0xFFFFFFFF;                   \
    E->u.syscall_info.ppid = -1;                                     \
    E->u.syscall_info.luid = -1;                                     \
    E->u.syscall_info.euid = bpf_get_current_uid_gid() >> 32;        \
    E->u.syscall_info.egid = bpf_get_current_uid_gid() & 0xFFFFFFFF; \
    E->u.syscall_info.mono_ns = bpf_ktime_get_ns();                  \
    E->u.syscall_info.syscall_pattern = SP;                          \
    bpf_get_current_comm(E->u.syscall_info.comm, sizeof(E->u.syscall_info.comm));

#define FILL_TELEMETRY_SYSCALL_RET(E, SP)

#define SET_OFFSET(CRC)                                   \
    offset = CRC;                                         \
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset); \
    if (!offset)                                          \
        goto Skip;

/* this must go in the kretprobe so we can grab the new process from `task_struct` */
#define GET_OFFSETS_4_8_RET_EXEC                                                                        \
    /* if "loaded" doesn't exist in the map, we get NULL back and won't read from offsets               \
     * when offsets are loaded into the offsets map, "loaded" should be given any value                 \
     */                                                                                                 \
    u64 offset = CRC_LOADED;                                                                            \
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset); /* squeezing out as much stack as possible */ \
    /* since we're using offsets to read from the structs, we don't need to bother with                 \
     * understanding their structure                                                                    \
     */                                                                                                 \
    u32 i_rdev = 0;                                                                                     \
    u64 i_ino = 0;                                                                                      \
    void *ts = (void *)bpf_get_current_task();                                                          \
    void *ptr = NULL;                                                                                   \
    if (ts && offset)                                                                                   \
    {                                                                                                   \
        read_value(ts, CRC_TASK_STRUCT_MM, &ptr, sizeof(ptr));                                          \
        read_value(ptr, CRC_MM_STRUCT_EXE_FILE, &ptr, sizeof(ptr));                                     \
        read_value(ptr, CRC_FILE_F_INODE, &ptr, sizeof(ptr));                                           \
        read_value(ptr, CRC_INODE_I_RDEV, &i_rdev, sizeof(i_rdev));                                     \
        read_value(ptr, CRC_INODE_I_INO, &i_ino, sizeof(i_ino));                                        \
    }

#define GET_OFFSETS_4_8                                                                                 \
    /* if "loaded" doesn't exist in the map, we get NULL back and won't read from offsets               \
     * when offsets are loaded into the offsets map, "loaded" should be given any value                 \
     */                                                                                                 \
    u64 offset = CRC_LOADED;                                                                            \
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset); /* squeezing out as much stack as possible */ \
    /* since we're using offsets to read from the structs, we don't need to bother with                 \
     * understanding their structure                                                                    \
     */                                                                                                 \
    void *ts = (void *)bpf_get_current_task();                                                          \
    void *ptr = NULL;                                                                                   \
    if (ts && offset)                                                                                   \
    {                                                                                                   \
        read_value(ts, CRC_TASK_STRUCT_REAL_PARENT, &ptr, sizeof(ptr));                                 \
        if (!ptr)                                                                                       \
            goto Skip;                                                                                  \
        read_value(ptr, CRC_TASK_STRUCT_PID, &ppid, sizeof(ppid));                                      \
        read_value(ts, CRC_TASK_STRUCT_LOGINUID, &luid, sizeof(luid));                                  \
        read_value(ts, CRC_TASK_STRUCT_MM, &ptr, sizeof(ptr));                                          \
        if (!ptr)                                                                                       \
            goto Skip;                                                                                  \
        read_value(ptr, CRC_MM_STRUCT_EXE_FILE, &ptr, sizeof(ptr));                                     \
        SET_OFFSET(CRC_FILE_F_PATH);                                                                    \
        ptr = ptr + *(u32 *)offset; /* ptr to f_path */                                                 \
        read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr));                                            \
        SET_OFFSET(CRC_DENTRY_D_NAME);                                                                  \
        ptr = ptr + *(u32 *)offset; /* ptr to d_name */                                                 \
        read_value(ptr, CRC_QSTR_LEN, &length, sizeof(length));                                         \
        read_value(ptr, CRC_QSTR_NAME, &exe, sizeof(exe));                                              \
    }

/**
 * A helper function for reading a value from a structure using the offsets map
 */
static __always_inline int read_value(void *base, u64 offset, void *dest, size_t dest_size)
{
    u64 _offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (_offset)
    {
        return bpf_probe_read(dest, dest_size, base + *(u32 *)_offset);
    }
    return -1;
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

static __always_inline void push_telemetry_event(struct pt_regs *ctx, ptelemetry_event_t ev)
{
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), ev, sizeof(*ev));
    __builtin_memset(ev, 0, sizeof(telemetry_event_t));
}

#define __READ_LOOP(PTR, T)                                                        \
    if (!br)                                                                       \
    {                                                                              \
        ev->u.v.truncated = FALSE;                                                 \
        ev->id = id;                                                               \
        ev->done = FALSE;                                                          \
        ev->telemetry_type = T;                                                    \
        count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)PTR + off); \
        if (count == VALUE_SIZE)                                                   \
        {                                                                          \
            ev->u.v.truncated = TRUE;                                              \
            off = off + VALUE_SIZE;                                                \
        }                                                                          \
        else                                                                       \
        {                                                                          \
            br = 1;                                                                \
        }                                                                          \
        push_telemetry_event(ctx, ev);                                             \
    }

#define __READ_LOOP_N(PTR, T, N) REPEAT_##N(__READ_LOOP(PTR, T);)

#define READ_LOOP(PTR, T)                                                      \
    ptr = 0;                                                                   \
    ret = bpf_probe_read(&ptr, sizeof(u64), (void *)PTR + (ii * sizeof(u64))); \
    if (ret < 0)                                                               \
    {                                                                          \
        goto Next;                                                             \
    }                                                                          \
    else if ((void *)ptr == NULL)                                              \
    {                                                                          \
        goto Next;                                                             \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        u32 off = 0;                                                           \
        char br = 0;                                                           \
        __READ_LOOP_N(ptr, T, 5);                                              \
    }                                                                          \
    ii++;

#define READ_LOOP_N(PTR, T, N) REPEAT_##N(READ_LOOP(PTR, T);)

#define READ_VALUE(EV, T, S)                                                     \
    if (!br)                                                                     \
    {                                                                            \
        EV->id = id;                                                             \
        EV->done = FALSE;                                                        \
        EV->telemetry_type = T;                                                  \
        EV->u.v.truncated = FALSE;                                               \
        count = 0;                                                               \
        count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)S + off); \
        if (count == VALUE_SIZE)                                                 \
        {                                                                        \
            EV->u.v.truncated = TRUE;                                            \
            off = off + VALUE_SIZE;                                              \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            br = 1;                                                              \
        }                                                                        \
        push_telemetry_event(ctx, EV);                                           \
    }

#define READ_VALUE_N(EV, T, S, N) REPEAT_##N(READ_VALUE(EV, T, S);)

#define SEND_PATH                                              \
    ev->id = id;                                               \
    ev->done = FALSE;                                          \
    ev->telemetry_type = TE_PWD;                               \
    if (br == 0)                                               \
    {                                                          \
        bpf_probe_read(&offset, sizeof(offset), ptr + name);   \
        if (!offset)                                           \
            goto Skip;                                         \
        bpf_probe_read(&count, sizeof(count), ptr + qstr_len); \
    }                                                          \
    temp = 0;                                                  \
    __builtin_memset(&ev->u.v.value, 0, VALUE_SIZE);           \
    if (count > (VALUE_SIZE - 1))                              \
        temp = VALUE_SIZE - 1;                                 \
    else                                                       \
        temp = count;                                          \
    bpf_probe_read(&ev->u.v.value, temp, (void *)offset);      \
    br = ev->u.v.value[0];                                     \
    if (count > VALUE_SIZE)                                    \
    {                                                          \
        br = 1;                                                \
        ev->u.v.truncated = TRUE;                              \
        offset = offset + VALUE_SIZE;                          \
        count = count - VALUE_SIZE;                            \
        push_telemetry_event(ctx, ev);                         \
    }                                                          \
    else                                                       \
    {                                                          \
        if (count != 0)                                        \
        {                                                      \
            ev->u.v.truncated = FALSE;                         \
            push_telemetry_event(ctx, ev);                     \
        }                                                      \
        /* we're done here, follow the pointer */              \
        bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);       \
        if (!ptr)                                              \
            goto Skip;                                         \
        if (br == '/')                                         \
            goto Skip;                                         \
        br = 0;                                                \
    }

#define SEND_PATH_N(N) REPEAT_##N(SEND_PATH;)

static __always_inline int enter_exec(syscall_pattern_type_t sp, int fd,
                                      const char __user *filename,
                                      const char __user *const __user *argv,
                                      const char __user *const __user *envp,
                                      int flags, struct pt_regs *ctx, u32 ppid,
                                      u32 luid, const char __user *exe, u32 len)
{
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&telemetry_ids, &pid_tgid, &id, BPF_ANY);
    return 0;
}

static __always_inline ptelemetry_event_t enter_exec_4_8(syscall_pattern_type_t sp, int fd,
                                                         const char __user *filename,
                                                         const char __user *const __user *argv,
                                                         const char __user *const __user *envp,
                                                         int flags, struct pt_regs *ctx, u32 ppid,
                                                         u32 luid, const char __user *exe, u32 len)
{
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    // if the ID already exists, we are tail-calling into ourselves, skip ahead to reading the path
    u64 p_t = bpf_get_current_pid_tgid();
    u64 id = (u64)bpf_map_lookup_elem(&telemetry_ids, &p_t);
    if (id)
    {
        __builtin_memcpy(&id, (void *)id, sizeof(u64));
        goto Pwd;
    }

    id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&telemetry_ids, &pid_tgid, &id, BPF_ANY);

    u32 count = 0;
    char br = 0;

Pwd:;
    u64 offset = 0;
    void *ptr = (void *)bpf_get_current_task();
    if (read_value(ptr, CRC_TASK_STRUCT_FS, &ptr, sizeof(ptr)) < 0)
        goto Skip;

    offset = CRC_FS_STRUCT_PWD;
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (!offset)
        goto Skip;
    ptr = ptr + *(u32 *)offset; // ptr to pwd

    if (read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr)) < 0)
        goto Skip;

    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 qstr_len = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    SET_OFFSET(CRC_QSTR_NAME);
    u32 name = qstr_len + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset; // offset of d_parent

    SET_OFFSET(CRC_QSTR_LEN);
    qstr_len = qstr_len + *(u32 *)offset; // offset of qstr length within qstr of dentry

    u32 temp = 0;
    SEND_PATH_N(9);
    bpf_tail_call(ctx, &tail_call_table, SYS_EXECVE_4_8);

Skip:
    ev->id = id;
    return ev;
}

SEC("kprobe/sys_exec_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_exec_tc_argv,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *idp = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);
    if (idp == NULL)
    {
        return 0;
    }
    u64 id = *idp;

    // put the event on the stack and satisfy the verifier
    telemetry_event_t tev = {0};
    ptelemetry_event_t ev = &tev;

    u32 index = 0;
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
    return 0;
}

SEC("kprobe/sys_exec_tc_envp")
int BPF_KPROBE_SYSCALL(kprobe__sys_exec_tc_envp,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 index = 0;
    u64 *idp = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);
    if (idp == NULL)
    {
        return 0;
    }
    u64 id = *idp;

    telemetry_event_t tev = {0};
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

Next:;
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
    const char __user *exe = NULL;
    u32 length = -1;
    // inode->i_rdev, inode->i_ino
    GET_OFFSETS_4_8;
    enter_exec_4_8(SP_EXECVEAT, fd, filename, argv, envp, flags, ctx, ppid, luid, exe, length);

Skip:
    return -1;
}

SEC("kprobe/sys_execve_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_4_8,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    enter_exec_4_8(SP_EXECVE, AT_FDCWD, filename, argv, envp, 0, ctx, ppid, luid, exe, length);

Skip:
    return -1;
}

SEC("kprobe/sys_execveat_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_4_11,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    // inode->i_rdev, inode->i_ino
    GET_OFFSETS_4_8;
    ptelemetry_event_t ev = enter_exec_4_8(SP_EXECVEAT, fd, filename, argv, envp, flags, ctx, ppid, luid, exe, length);

    if (!filename)
        goto Skip;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *idp = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);
    if (idp == NULL)
    {
        return 0;
    }
    u64 id = *idp;

    __builtin_memset(ev, 0, sizeof(telemetry_event_t));
    u32 count = 0;
    u64 off = 0;
    char br = 0;
    READ_VALUE_N(ev, TE_EXEC_FILENAME, filename, 5);

    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_TC_ARGV);

Skip:
    return -1;
}

SEC("kprobe/sys_execve_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_4_11,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    ptelemetry_event_t ev = enter_exec_4_8(SP_EXECVE, AT_FDCWD, filename, argv, envp, 0, ctx, ppid, luid, exe, length);

    if (!filename)
        goto Skip;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *idp = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);
    if (idp == NULL)
    {
        return 0;
    }
    u64 id = *idp;

    __builtin_memset(ev, 0, sizeof(telemetry_event_t));
    u32 count = 0;
    u64 off = 0;
    char br = 0;
    READ_VALUE_N(ev, TE_EXEC_FILENAME, filename, 5);

    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_TC_ARGV);

Skip:
    return -1;
}

SEC("kprobe/sys_execveat")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    return enter_exec(SP_EXECVEAT, fd, filename, argv, envp, flags, ctx, -1, -1, NULL, -1);
}

SEC("kprobe/sys_execve")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    return enter_exec(SP_EXECVE, AT_FDCWD, filename, argv, envp, 0, ctx, -1, -1, NULL, -1);
}

static __always_inline int exit_exec(struct pt_regs *__ctx, u32 i_rdev, u64 i_ino)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .done = FALSE,
        .telemetry_type = TE_UNSPEC,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };
    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid_tgid);

    file_info_t fi = {
        .inode = i_ino,
        .devmajor = MAJOR(i_rdev),
        .devminor = MINOR(i_rdev),
        .value[0] = '\0',
    };

    ev->telemetry_type = TE_FILE_INFO;
    __builtin_memcpy(&ev->u.file_info, &fi, sizeof(fi));
    push_telemetry_event(__ctx, ev);

    ev->id = *id;
    ev->done = TRUE;
    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(__ctx);
    push_telemetry_event(__ctx, ev);

Flush:
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    _sock sk = (_sock)PT_REGS_PARM1(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tcpv4_connect, &index, &sk, BPF_ANY);

    return 0;
}

SEC("kprobe/ip_local_out")
int kprobe__ip_local_out(struct pt_regs *ctx)
{
    _skbuff sk = (_skbuff)PT_REGS_PARM3(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&udpv4_sendmsg_map, &index, &sk, BPF_ANY);

    return 0;
}

SEC("kprobe/ip6_local_out")
int kprobe__ip6_local_out(struct pt_regs *ctx)
{
    _skbuff sk = (_skbuff)PT_REGS_PARM3(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&udpv6_sendmsg_map, &index, &sk, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
    _sock sk = (_sock)PT_REGS_PARM1(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tcpv6_connect, &index, &sk, BPF_ANY);

    return 0;
}

// This handles outgoing udp packets
SEC("kretprobe/ret_ip6_local_out")
int kretprobe__ret_ip6_local_out(struct pt_regs *ctx)
{
    unsigned char *skb_head = NULL;
    unsigned short transport_header = 0;
    unsigned short network_header = 0;
    unsigned char proto = 0;
    _skbuff *skpp;

    int ret = PT_REGS_RC(ctx);
    if (ret < 0)
    {
        return 0;
    }

    // Just to be safe 0 out the structs
    telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.direction = outbound;
    ev.u.network_info.ip_type = AF_INET6;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();

    // Save the pid in the event structure
    ev.u.network_info.process.pid = index;

    // Lookup the corresponding *sk that we saved when tcp_v4_connect was called
    skpp = bpf_map_lookup_elem(&udpv6_sendmsg_map, &index);
    if (skpp == NULL)
    {
        return 0;
    }

    unsigned char *skbuff_base = (unsigned char *)*skpp;
    if (skbuff_base == NULL)
    {
        return 0;
    }

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);

    ret = read_value(skbuff_base, CRC_SKBUFF_HEAD, &skb_head, sizeof(skb_head));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header));
    if (ret == -1)
    {
        return 0;
    }

    if (!loaded)
    {
        return 0;
    }

    struct ipv6hdr *ip = (struct ipv6hdr *)(skb_head + network_header);
    bpf_probe_read(&proto, sizeof(proto), (void *)(&ip->nexthdr));

    if (proto == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
        bpf_probe_read(&ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr), (void *)(&ip->daddr));
        bpf_probe_read(&ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr), (void *)(&ip->saddr));
        bpf_probe_read(&ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port), (void *)(&udp->dest));
        bpf_probe_read(&ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port), (void *)(&udp->source));
        ev.u.network_info.protocol_type = IPPROTO_UDP;
        ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    }
    else
    {
        // Not udp and therefore we ignore it. We only want udp packets
        return 0;
    }
    // Get Process data and set pid and comm string
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

SEC("kretprobe/ret_inet_csk_accept")
int kretprobe__ret_inet_csk_accept(struct pt_regs *ctx)
{
    // Get the return value from inet_csk_accept
    unsigned char *sk_base = (unsigned char *)PT_REGS_RC(ctx);

    // Just to be safe 0 out the structs
    telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    if (sk_base == NULL)
    {
        return 0;
    }

    ev.u.network_info.direction = inbound;
    ev.u.network_info.protocol_type = IPPROTO_TCP;

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    int ret = read_value(sk_base, CRC_SOCK_COMMON_FAMILY, &ev.u.network_info.ip_type, sizeof(ev.u.network_info.ip_type));
    if (ret == -1)
    {
        return 0;
    }

    if (ev.u.network_info.ip_type == AF_INET && loaded)
    {
        read_value(sk_base, CRC_SOCK_COMMON_SADDR, &ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr));
        read_value(sk_base, CRC_SOCK_COMMON_DADDR, &ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
        read_value(sk_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
        ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    }
    else if (ev.u.network_info.ip_type == AF_INET6 && loaded)
    {
        read_value(sk_base, CRC_SOCK_COMMON_DADDR6, &ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SADDR6, &ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
        read_value(sk_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
        ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    }

    // Get Process data and set pid and comm string
    ev.u.network_info.process.pid = (u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

SEC("kretprobe/ret_tcp_v4_connect")
int kretprobe__ret_tcp_v4_connect(struct pt_regs *ctx)
{
    // Get the return value from tcp_v4_connect
    int ret = PT_REGS_RC(ctx);

    /* if "loaded" doesn't exist in the map, we get NULL back and won't read from offsets              
     * when offsets are loaded into the offsets map, "loaded" should be given any value                
     */
    u64 loaded = CRC_LOADED; // CRC64 of "loaded"
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);

    // Just to be safe 0 out the structs
    telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();
    _sock *skpp;

    // Lookup the corresponding *sk that we saved when tcp_v4_connect was called
    skpp = bpf_map_lookup_elem(&tcpv4_connect, &index);
    if (skpp == 0)
    {
        return 0;
    }

    // Deref
    _sock skp = *skpp;
    unsigned char *skp_base = (unsigned char *)skp;
    if (skp_base == NULL)
    {
        return 0;
    }

    // failed to send SYNC packet, may not have populated
    // socket __sk_common.{skc_rcv_saddr, ...}
    if (ret != 0)
    {
        return 0;
    }

    // TODO: Need to integrate this with lkccb to get correct offsets
    // TODO: Since we are tracking connect isn't this always outbound?
    ev.u.network_info.direction = outbound;
    ev.u.network_info.protocol_type = IPPROTO_TCP;
    ev.u.network_info.ip_type = AF_INET;

    if (loaded && skp_base)
    {
        read_value(skp_base, CRC_SOCK_COMMON_DADDR, &ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr));
        read_value(skp_base, CRC_SOCK_COMMON_SADDR, &ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr));
        read_value(skp_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
        read_value(skp_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
        ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port); // Get the endianness right before returning it
    }

    // Get Process data and set pid and comm string
    ev.u.network_info.process.pid = index;
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

// This handles both IPv4 and IPv6 udp packets
SEC("kretprobe/ret___skb_recv_udp")
int kretprobe__ret___skb_recv_udp(struct pt_regs *ctx)
{
    telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();

    _skbuff skb = (_skbuff)PT_REGS_RC_CORE(ctx);
    unsigned char *skbuff_base = (unsigned char *)skb;

    if (skbuff_base == NULL)
    {
        return 0;
    }

    ev.u.network_info.direction = inbound;
    ev.u.network_info.protocol_type = IPPROTO_UDP;

    unsigned char *skb_head = NULL;
    unsigned short transport_header = 0;
    unsigned short network_header = 0;
    __be16 proto = 0;

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);

    int ret = read_value(skbuff_base, CRC_SKBUFF_HEAD, &skb_head, sizeof(skb_head));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_SKBUFF_PROTO, &proto, sizeof(proto));
    if (ret == -1)
    {
        return 0;
    }

    u64 eth_proto_offset = CRC_SKBUFF_PROTO;
    eth_proto_offset = (u64)bpf_map_lookup_elem(&offsets, &eth_proto_offset);

    if (!loaded)
    {
        return 0;
    }

    if (proto == 0xDD86) // ETH_P_IPv6
    {
        struct ipv6hdr *ip = (struct ipv6hdr *)(skb_head + network_header);
        struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
        ev.u.network_info.ip_type = AF_INET6;
        bpf_probe_read(&ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr), (void *)(&ip->daddr));
        bpf_probe_read(&ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr), (void *)(&ip->saddr));
        bpf_probe_read(&ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port), (void *)(&udp->dest));
        bpf_probe_read(&ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port), (void *)(&udp->source));
    }
    else if (proto == 0x8) // ETH_P_IP
    {
        struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
        struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
        ev.u.network_info.ip_type = AF_INET;
        bpf_probe_read(&ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr), (void *)(&ip->daddr));
        bpf_probe_read(&ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr), (void *)(&ip->saddr));
        bpf_probe_read(&ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port), (void *)(&udp->dest));
        bpf_probe_read(&ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port), (void *)(&udp->source));
    }
    else // All other protocols we just ignore
    {
        return 0;
    }
    ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port);

    // Get Process data and set pid and comm string
    ev.u.network_info.process.pid = index;
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

// This handles outgoing udp packets
SEC("kretprobe/ret_ip_local_out")
int kretprobe__ret_ip_local_out(struct pt_regs *ctx)
{
    unsigned char *skb_head = NULL;
    unsigned short transport_header = 0;
    unsigned short network_header = 0;
    unsigned char proto = 0;
    _skbuff *skpp;

    int ret = PT_REGS_RC(ctx);
    if (ret < 0)
    {
        return 0;
    }

    // Just to be safe 0 out the structs
    telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.direction = outbound;
    ev.u.network_info.ip_type = AF_INET;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();

    // Save the pid in the event structure
    ev.u.network_info.process.pid = index;

    // Lookup the corresponding sk_buff* that we saved when ip_local_out was called
    skpp = bpf_map_lookup_elem(&udpv4_sendmsg_map, &index);
    if (skpp == NULL)
    {
        return 0;
    }

    _skbuff skp = *skpp;
    unsigned char *skbuff_base = (unsigned char *)skp;
    if (skbuff_base == NULL)
    {
        return 0;
    }

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);

    ret = read_value(skbuff_base, CRC_SKBUFF_HEAD, &skb_head, sizeof(skb_head));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header));
    if (ret == -1)
    {
        return 0;
    }

    if (!loaded)
    {
        return 0;
    }

    struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
    bpf_probe_read(&proto, sizeof(proto), (void *)(&ip->protocol));

    if (proto == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
        bpf_probe_read(&ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr), (void *)(&ip->daddr));
        bpf_probe_read(&ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr), (void *)(&ip->saddr));
        bpf_probe_read(&ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port), (void *)(&udp->source));
        bpf_probe_read(&ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port), (void *)(&udp->dest));
        ev.u.network_info.protocol_type = IPPROTO_UDP;
        ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port);
        ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    }
    else
    {
        // Not udp and therefore we ignore it. We only want udp packets
        return 0;
    }

    // Get Process data and set pid and comm string
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

SEC("kretprobe/ret_tcp_v6_connect")
int kretprobe__ret_tcp_v6_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    /* if "loaded" doesn't exist in the map, we get NULL back and won't read from offsets              
     * when offsets are loaded into the offsets map, "loaded" should be given any value                
     */
    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded); /* squeezing out as much stack as possible */
    /* since we're using offsets to read from the structs, we don't need to bother with                
     * understanding their structure                                                                   
     */

    // Just to be safe 0 out the structs
    telemetry_event_t ev;
    memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();
    _sock *skpp;

    skpp = bpf_map_lookup_elem(&tcpv6_connect, &index);
    if (skpp == 0)
    {
        return 0;
    }

    // Deref
    _sock skp = *skpp;
    unsigned char *skp_base = (unsigned char *)skp;
    if (skp_base == NULL)
    {
        return 0;
    }

    // failed to send SYNC packet, may not have populated
    // socket __sk_common.{skc_rcv_saddr, ...}
    if (ret != 0)
    {
        return 0;
    }

    ev.u.network_info.direction = outbound;
    ev.u.network_info.protocol_type = IPPROTO_TCP;
    ev.u.network_info.ip_type = AF_INET6;

    if (loaded)
    {
        read_value(skp_base, CRC_SOCK_COMMON_DADDR6, &ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr));
        read_value(skp_base, CRC_SOCK_COMMON_SADDR6, &ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr));
        read_value(skp_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
        read_value(skp_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
        ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port);
    }

    // Get Process data and set pid and comm string
    ev.u.network_info.process.pid = index;
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &telemetry_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

SEC("kretprobe/ret_sys_execve")
int kretprobe__ret_sys_execve(struct pt_regs *ctx)
{
    return exit_exec(ctx, -1, -1);
}

SEC("kretprobe/ret_sys_execveat")
int kretprobe__ret_sys_execveat(struct pt_regs *ctx)
{
    return exit_exec(ctx, -1, -1);
}

SEC("kretprobe/ret_sys_execve_4_8")
int kretprobe__ret_sys_execve_4_8(struct pt_regs *ctx)
{
    GET_OFFSETS_4_8_RET_EXEC;
    return exit_exec(ctx, i_rdev, i_ino);
}

SEC("kretprobe/ret_sys_execveat_4_8")
int kretprobe__ret_sys_execveat_4_8(struct pt_regs *ctx)
{
    GET_OFFSETS_4_8_RET_EXEC;
    return exit_exec(ctx, i_rdev, i_ino);
}

static __always_inline int enter_clone(syscall_pattern_type_t sp, unsigned long flags,
                                       void __user *stack, int __user *parent_tid,
                                       int __user *child_tid, unsigned long tls,
                                       struct pt_regs *ctx, u32 ppid, u32 luid,
                                       const char __user *exe, u32 len)
{
    // explicit memcpy to move the struct to the stack and satisfy the verifier
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXE_PATH;
    ev->u.v.truncated = FALSE;
    long count = 0;
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)exe);
    if (count == VALUE_SIZE)
    {
        ev->u.v.truncated = TRUE;
    }
    push_telemetry_event(ctx, ev);

    clone_info_t clone_info = {
        .flags = flags,
        .stack = (u64)stack,
        .parent_tid = -1,
        .child_tid = -1,
        .tls = tls,
        .p_ptr = (u64)parent_tid,
        .c_ptr = (u64)child_tid,
    };

    u32 key = 0;
    bpf_map_update_elem(&clone_info_store, &key, &clone_info, BPF_ANY);

    bpf_map_update_elem(&telemetry_ids, &pid_tgid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_clone(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
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
        .stack = (u64)pclone_info->stack,
        .parent_tid = -1,
        .child_tid = -1,
        .tls = pclone_info->tls,
        .p_ptr = pclone_info->p_ptr,
        .c_ptr = pclone_info->c_ptr,
    };

    bpf_probe_read(&clone_info.parent_tid, sizeof(u32), (void *)pclone_info->p_ptr);
    bpf_probe_read(&clone_info.child_tid, sizeof(u32), (void *)pclone_info->c_ptr);
    ev->u.clone_info = clone_info;
    push_telemetry_event(ctx, ev);

    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid_tgid);
    ev->done = TRUE;
    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ctx, ev);

Flush:
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
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_clone(SP_CLONE, flags, stack, parent_tid, child_tid, tls, ctx, ppid, luid, exe, length);
Skip:
    return -1;
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
    return enter_clone(SP_CLONE, flags, stack, parent_tid, child_tid, tls, ctx, -1, -1, NULL, -1);
}

static __always_inline int enter_clone3(syscall_pattern_type_t sp, struct clone_args __user *uargs,
                                        size_t size, struct pt_regs *ctx, u32 ppid, u32 luid,
                                        const char __user *exe, u32 len)
{
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);

    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ctx, ev);
    pid_tgid = pid_tgid >> 32;
    bpf_map_update_elem(&telemetry_ids, (u32 *)&pid_tgid, &id, BPF_ANY);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXE_PATH;
    ev->u.v.truncated = FALSE;
    long count = 0;
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)exe);
    if (count == VALUE_SIZE)
    {
        ev->u.v.truncated = TRUE;
    }
    push_telemetry_event(ctx, ev);

    clone3_info_t clone3_info = {0};
    clone3_info.size = (u64)size;

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
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
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
    clone_info.stack = (u64)pclone3_info->stack;
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

    bpf_probe_read(&clone_info.parent_tid, sizeof(u32), (void *)clone_info.p_ptr);
    bpf_probe_read(&clone_info.child_tid, sizeof(u32), (void *)clone_info.c_ptr);
    ev->u.clone3_info = clone_info;
    push_telemetry_event(ctx, ev);

    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid_tgid);
    ev->done = TRUE;
    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ctx, ev);

Flush:
    return 0;
}

SEC("kprobe/sys_clone3")
int BPF_KPROBE_SYSCALL(kprobe__sys_clone3, struct clone_args __user *uargs, size_t size)
{
    // clone3 was added in 5.3, so this should always be available if clone3 is attachable
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_clone3(SP_CLONE3, uargs, size, ctx, ppid, luid, exe, length);
Skip:
    return -1;
}

SEC("kretprobe/ret_sys_clone3")
int kretprobe__ret_sys_clone3(struct pt_regs *ctx)
{
    return exit_clone3(ctx);
}

SEC("kprobe/sys_fork")
int BPF_KPROBE_SYSCALL(kprobe__sys_fork)
{
    return enter_clone(SP_FORK, 0, NULL, NULL, NULL, 0, ctx, -1, -1, NULL, -1);
}

SEC("kprobe/sys_vfork")
int BPF_KPROBE_SYSCALL(kprobe__sys_vfork)
{
    return enter_clone(SP_VFORK, 0, NULL, NULL, NULL, 0, ctx, -1, -1, NULL, -1);
}

SEC("kprobe/sys_fork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_fork_4_8)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_clone(SP_FORK, 0, NULL, NULL, NULL, 0, ctx, ppid, luid, exe, length);
Skip:
    return -1;
}

SEC("kprobe/sys_vfork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_vfork_4_8)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_clone(SP_VFORK, 0, NULL, NULL, NULL, 0, ctx, ppid, luid, exe, length);
Skip:
    return -1;
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
                                         struct pt_regs *ctx, u32 ppid, u32 luid,
                                         const char __user *exe, u32 len)
{
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXE_PATH;
    ev->u.v.truncated = FALSE;
    long count = 0;
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)exe);
    if (count == VALUE_SIZE)
    {
        ev->u.v.truncated = TRUE;
    }
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_UNSHARE_FLAGS;
    ev->u.unshare_flags = flags;
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&telemetry_ids, &pid_tgid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_unshare(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .done = TRUE,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };
    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid_tgid);

    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ctx, ev);

Flush:
    return 0;
}

SEC("kprobe/sys_unshare_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_unshare_4_8, int flags)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_unshare(SP_UNSHARE, flags, ctx, ppid, luid, exe, length);
Skip:
    return -1;
}

SEC("kprobe/sys_unshare")
int BPF_KPROBE_SYSCALL(kprobe__sys_unshare, int flags)
{
    return enter_unshare(SP_UNSHARE, flags, ctx, -1, -1, NULL, -1);
}

SEC("kretprobe/ret_sys_unshare")
int kretprobe__ret_sys_unshare(struct pt_regs *ctx)
{
    return exit_unshare(ctx);
}

static __always_inline int enter_exit(syscall_pattern_type_t sp, int status,
                                      struct pt_regs *ctx, u32 ppid, u32 luid,
                                      const char __user *exe, u32 len)

{
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();
    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = 0,
    ev->u.v.value[0] = '\0';
    ev->u.v.truncated = FALSE;

    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp);
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXE_PATH;
    ev->u.v.truncated = FALSE;
    long count = 0;
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)exe);
    if (count == VALUE_SIZE)
    {
        ev->u.v.truncated = TRUE;
    }
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->done = FALSE;
    ev->telemetry_type = TE_EXIT_STATUS;
    ev->u.exit_status = status;
    push_telemetry_event(ctx, ev);
    bpf_map_update_elem(&telemetry_ids, &pid_tgid, &id, BPF_ANY);

    bpf_tail_call(ctx, &tail_call_table, RET_SYS_EXIT);

    return 0;
}

static __always_inline int exit_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&telemetry_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .done = TRUE,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };
    ev->id = *id;
    bpf_map_delete_elem(&telemetry_ids, &pid_tgid);

    ev->telemetry_type = TE_RETCODE;
    ev->u.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ctx, ev);

Flush:
    return 0;
}

SEC("kprobe/sys_exit_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_4_8, int status)
{
    // if PID != TGID, then exit, we only care when the entire group exits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) ^ (pid_tgid & 0xFFFFFFFF))
        return 0;

    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_exit(SP_EXIT, status, ctx, ppid, luid, exe, length);
Skip:
    return -1;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit, int status)
{
    // if PID != TGID, then exit, we only care when the entire group exits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) ^ (pid_tgid & 0xFFFFFFFF))
        return 0;
    return enter_exit(SP_EXIT, status, ctx, -1, -1, NULL, -1);
}

SEC("kprobe/sys_exit_group_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_group_4_8, int status)
{
    u32 ppid = -1;
    u32 luid = -1;
    const char __user *exe = NULL;
    u32 length = -1;
    GET_OFFSETS_4_8;
    return enter_exit(SP_EXITGROUP, status, ctx, ppid, luid, exe, length);
Skip:
    return -1;
}

SEC("kprobe/sys_exit_group")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_group, int status)
{
    return enter_exit(SP_EXITGROUP, status, ctx, -1, -1, NULL, -1);
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
