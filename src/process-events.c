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
#include "repeat.h"
#include "common.h"

#define CLONE_ARGS_SIZE_VER0 64 /* sizeof first published struct */
#define CLONE_ARGS_SIZE_VER1 80 /* sizeof second published struct */
#define CLONE_ARGS_SIZE_VER2 88 /* sizeof third published struct */

struct bpf_map_def SEC("maps/mount_events") mount_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
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

struct bpf_map_def SEC("maps/read_path_skip") read_path_skip = {
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

struct bpf_map_def SEC("maps/process_events") process_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/process_ids") process_ids = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
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

#define FILL_TELEMETRY_SYSCALL_EVENT(E, SP, PPID, LUID) \
    u64 pid_tgid = bpf_get_current_pid_tgid();          \
    u64 uid_gid = bpf_get_current_uid_gid();            \
    E->telemetry_type = TE_SYSCALL_INFO;                \
    E->u.syscall_info.pid = pid_tgid >> 32;             \
    E->u.syscall_info.tid = pid_tgid & 0xFFFFFFFF;      \
    E->u.syscall_info.ppid = PPID;                      \
    E->u.syscall_info.luid = LUID;                      \
    E->u.syscall_info.euid = uid_gid >> 32;             \
    E->u.syscall_info.egid = uid_gid & 0xFFFFFFFF;      \
    E->u.syscall_info.mono_ns = bpf_ktime_get_ns();     \
    E->u.syscall_info.syscall_pattern = SP;

#define GET_OFFSETS_4_8                                                                                 \
    /* if "loaded" doesn't exist in the map, we get NULL back and won't read from offsets               \
     * when offsets are loaded into the offsets map, "loaded" should be given any value                 \
     */                                                                                                 \
    u64 offset = CRC_LOADED;                                                                            \
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset); /* squeezing out as much stack as possible */ \
    /* if CRC_LOADED is not in the map it means we are too early in the ebpf program loading       */   \
    if (!offset)                                                                                        \
    {                                                                                                   \
        return 0;                                                                                       \
    }                                                                                                   \
    /* since we're using offsets to read from the structs, we don't need to bother with                 \
     * understanding their structure                                                                    \
     */                                                                                                 \
    void *ts = (void *)bpf_get_current_task();                                                          \
    void *ptr = NULL;                                                                                   \
    if (ts)                                                                                             \
    {                                                                                                   \
        read_value(ts, CRC_TASK_STRUCT_REAL_PARENT, &ptr, sizeof(ptr));                                 \
        read_value(ptr, CRC_TASK_STRUCT_TGID, &ppid, sizeof(ppid));                                     \
        read_value(ts, CRC_TASK_STRUCT_LOGINUID, &luid, sizeof(luid));                                  \
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
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));

    return 0;
}

static __always_inline void push_telemetry_event(struct pt_regs *ctx, ptelemetry_event_t ev)
{
    // check mm field of task_struct
    // skip pushing kernel process events as they have an mm field of NULL
    void *ts = (void *)bpf_get_current_task();
    void *ptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_MM, &ptr, sizeof(ptr));
    if (!ptr) return;

    bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
    __builtin_memset(ev, 0, sizeof(telemetry_event_t));
}

#define READ_VALUE(EV, T, PTR)                                                         \
    if (!br)                                                                           \
    {                                                                                  \
        EV->id = id;                                                                   \
        EV->telemetry_type = T;                                                        \
        EV->u.v.truncated = FALSE;                                                     \
        int count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)PTR + off); \
        if (count < 0)                                                                 \
        {                                                                              \
            goto Next;                                                                 \
        }                                                                              \
        if (count == VALUE_SIZE)                                                       \
        {                                                                              \
            EV->u.v.truncated = TRUE;                                                  \
            off = off + VALUE_SIZE;                                                    \
        }                                                                              \
        else                                                                           \
        {                                                                              \
            br = 1;                                                                    \
        }                                                                              \
        push_telemetry_event(ctx, EV);                                                 \
    }

#define READ_VALUE_N(EV, T, PTR, N) REPEAT_##N(READ_VALUE(EV, T, PTR);)

#define READ_LOOP(PTR, T)                                                      \
    ptr = NULL;                                                                \
    ret = bpf_probe_read(&ptr, sizeof(ptr), (void *)PTR + (ii * sizeof(PTR))); \
    if (ret < 0)                                                               \
    {                                                                          \
        goto Next;                                                             \
    }                                                                          \
    else if (ptr == NULL)                                                      \
    {                                                                          \
        goto Next;                                                             \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        u32 off = 0;                                                           \
        char br = 0;                                                           \
        READ_VALUE_N(ev, T, ptr, 5);                                           \
    }                                                                          \
    ii++;

#define READ_LOOP_N(PTR, T, N) REPEAT_##N(READ_LOOP(PTR, T);)

#define SKIP_PATH                                    \
    if (skipped >= to_skip)                          \
        goto Send;                                   \
    /* Skip to the parent directory */               \
    bpf_probe_read(&ptr, sizeof(ptr), ptr + parent); \
    skipped += 1;                                    \
    if (!ptr)                                        \
        goto Send;

#define SKIP_PATH_N(N) REPEAT_##N(SKIP_PATH;)

#define SEND_PATH(T)                                                        \
    if (br == 0)                                                            \
    {                                                                       \
        if (bpf_probe_read(&offset, sizeof(offset), ptr + name) < 0)        \
            goto Skip;                                                      \
        if (!offset)                                                        \
            goto Skip;                                                      \
    }                                                                       \
    ev->telemetry_type = T;                                                 \
    ev->id = id;                                                            \
    __builtin_memset(&ev->u.v.value, 0, VALUE_SIZE);                        \
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, offset);         \
    if (count < 0)                                                          \
    {                                                                       \
        goto Skip;                                                          \
    }                                                                       \
    else if (count == VALUE_SIZE)                                           \
    {                                                                       \
        br = 1;                                                             \
        ev->u.v.truncated = TRUE;                                           \
        offset = offset + VALUE_SIZE;                                       \
        push_telemetry_event(ctx, ev);                                      \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        /* save it here since push_telemetry_event clears ev */             \
        br = ev->u.v.value[0];                                              \
        ev->u.v.truncated = FALSE;                                          \
        push_telemetry_event(ctx, ev);                                      \
        if (br == '/')                                                      \
            goto Skip;                                                      \
        /* we're done here, follow the pointer */                           \
        void *old_ptr = ptr;                                                \
        bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);                    \
        if (!ptr || old_ptr == ptr)                                         \
            goto Skip;                                                      \
        to_skip += 1;                                                       \
        br = 0;                                                             \
    }

#define SEND_PATH_N(N, T) REPEAT_##N(SEND_PATH(T);)

static __always_inline bool check_discard(struct pt_regs *ctx, ptelemetry_event_t ev, u64 *id)
{
    u32 retcode = (u32)PT_REGS_RC(ctx);
    if (retcode != 0) {
        ev->id = *id;
        ev->telemetry_type = TE_DISCARD;
        ev->u.r.retcode = retcode;
        push_telemetry_event(ctx, ev);

        return true;
    }

    return false;
}

static __always_inline void* get_current_exe()
{
    u64 offset_key = CRC_LOADED;
    void *offset = bpf_map_lookup_elem(&offsets, &offset_key);
    if (!offset)
        return NULL;

    void *ts = (void *)bpf_get_current_task();
    if (!ts)
        return NULL;

    void *ptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_MM, &ptr, sizeof(ptr));
    read_value(ptr, CRC_MM_STRUCT_EXE_FILE, &ptr, sizeof(ptr));

    return ptr;
}

// it's argument should be a pointer to a file
static __always_inline file_info_t extract_file_info(void *ptr)
{
    u32 i_dev = 0;
    u64 i_ino = 0;
    void *sptr = NULL;
    read_value(ptr, CRC_FILE_F_INODE, &ptr, sizeof(ptr));
    read_value(ptr, CRC_INODE_I_SB, &sptr, sizeof(sptr));
    read_value(sptr, CRC_SBLOCK_S_DEV, &i_dev, sizeof(i_dev));
    read_value(ptr, CRC_INODE_I_INO, &i_ino, sizeof(i_ino));

    return (file_info_t) {
        .inode = i_ino,
        .devmajor = MAJOR(i_dev),
        .devminor = MINOR(i_dev),
    };
}

static __always_inline void push_exit_exec(struct pt_regs *ctx, u64 id,
                                           file_info_t file_info, ptelemetry_event_t ev)
{
    ev->id = id;
    ev->telemetry_type = TE_FILE_INFO;
    ev->u.file_info = file_info;
    bpf_get_current_comm(&ev->u.file_info.comm, sizeof(ev->u.file_info.comm));
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->telemetry_type = TE_RETCODE;
    ev->u.r.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ctx, ev);
}

static __always_inline void push_path(struct pt_regs *ctx, ptelemetry_event_t ev,
                                      void *ptr, tail_call_slot_t slot,
                                      telemetry_event_type_t type, u64 id) {
    if (read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr)) < 0) // path->d_entry
        goto Skip;

    void *offset = NULL;
    u64 offset_key = 0;

    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 name = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    SET_OFFSET(CRC_QSTR_NAME);
    name = name + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset; // offset of d_parent

    u32 to_skip = 0;
    u32 *to_skip_p = (u32 *)bpf_map_lookup_elem(&read_path_skip, &to_skip);
    if (to_skip_p)
    {
        to_skip = *to_skip_p;
    }

    u32 skipped = 0;
    if (to_skip != 0)
    {
        SKIP_PATH_N(125);
    }

Send:;
    char br = 0;
    int count = 0;
    SEND_PATH_N(10, type);

    // update to_skip, reuse skipped as index by resetting it
    skipped = 0;
    bpf_map_update_elem(&read_path_skip, &skipped, &to_skip, BPF_ANY);

    // tail call back in
    bpf_tail_call(ctx, &tail_call_table, slot);

Skip:
    skipped = 0;
    bpf_map_delete_elem(&read_path_skip, &skipped);
}

static __always_inline int process_argv(struct pt_regs *ctx,
                                        const char __user *const __user *argv,
                                        u32 tail_index) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *idp = bpf_map_lookup_elem(&process_ids, &pid_tgid);
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

    u32 ii = *pii;
    char *ptr = NULL;
    int ret = 0;

    // this number was arrived at experimentally, increasing it will result in too many
    // instructions for older kernels
    READ_LOOP_N(argv, TE_COMMAND_LINE, 6);

    bpf_map_update_elem(&read_flush_index, &index, &ii, BPF_ANY);

Tail:
    bpf_tail_call(ctx, &tail_call_table, tail_index);

Next:;
    u32 reset = 0;
    bpf_map_update_elem(&read_flush_index, &reset, &reset, BPF_ANY);
    return 0;
}

static __always_inline int enter_exec(syscall_pattern_type_t sp,
                                      struct pt_regs *ctx)
{
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();

    ev->id = id;
    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp, -1, -1);
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&process_ids, &pid_tgid, &id, BPF_ANY);
    return 0;
}

static __always_inline u64 enter_exec_4_11(syscall_pattern_type_t sp,
                                           struct pt_regs *ctx,
                                           u32 ppid, u32 luid,
                                           ptelemetry_event_t ev)
{
    // if the ID already exists, we are tail-calling into ourselves, skip ahead to reading the path
    u64 p_t = bpf_get_current_pid_tgid();
    u64 *id_p = bpf_map_lookup_elem(&process_ids, &p_t);
    u64 id = 0;
    if (id_p)
    {
        id = *id_p;
        goto Pwd;
    }

    id = bpf_get_prandom_u32();

    ev->id = id;
    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp, ppid, luid);
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&process_ids, &pid_tgid, &id, BPF_ANY);

    u32 to_skip = 0;
    bpf_map_update_elem(&read_path_skip, &to_skip, &to_skip, BPF_ANY);

Pwd:;
    // the verifier complains if these are instantiated before the Pwd:; label
    void *ptr = (void *)bpf_get_current_task();
    if (read_value(ptr, CRC_TASK_STRUCT_FS, &ptr, sizeof(ptr)) < 0) // task_struct->fs
        return id;

    ptr = offset_ptr(ptr, CRC_FS_STRUCT_PWD); // &(fs->pwd)
    if (ptr == NULL)
        return id;

    push_path(ctx, ev, ptr, SYS_EXECVE_4_11, TE_PWD, id);

    return id;
}

SEC("kprobe/sys_execve_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_tc_argv,
                       const char __user *filename,
                       const char __user *const __user *argv)
{
    return process_argv(ctx, argv, SYS_EXECVE_TC_ARGV);
}

SEC("kprobe/sys_execveat_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_tc_argv,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv)
{
    return process_argv(ctx, argv, SYS_EXECVEAT_TC_ARGV);
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
    GET_OFFSETS_4_8;

    // create the event early so it can be re-used to save stack space
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    enter_exec_4_11(SP_EXECVEAT, ctx, ppid, luid, ev);

    bpf_tail_call(ctx, &tail_call_table, SYS_EXECVEAT_TC_ARGV);

    return 0;
}

SEC("kprobe/sys_execve_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_4_11,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;

    // create the event early so it can be re-used to save stack space
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = enter_exec_4_11(SP_EXECVE, ctx, ppid, luid, ev);

    if (!filename)
        goto Next;

    __builtin_memset(ev, 0, sizeof(telemetry_event_t));
    u64 off = 0;
    char br = 0;
    READ_VALUE_N(ev, TE_EXEC_FILENAME, filename, 5);

    bpf_tail_call(ctx, &tail_call_table, SYS_EXECVE_TC_ARGV);

Next:
    return 0;
}

SEC("kprobe/sys_execveat")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    return enter_exec(SP_EXECVEAT, ctx);
}

SEC("kprobe/sys_execve")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    return enter_exec(SP_EXECVE, ctx);
}

SEC("kretprobe/ret_sys_execve")
int kretprobe__ret_sys_execve(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (!id)
        return 0;

    // re-use the same ev to save stack space
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    if (check_discard(ctx, ev, id))
        goto Done;

    push_exit_exec(ctx, *id, (file_info_t) {
        .inode = 0,
        .devmajor = 0,
        .devminor = 0,
    }, ev);

 Done:
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    return 0;
}

SEC("kretprobe/ret_sys_execveat")
int kretprobe__ret_sys_execveat(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (!id)
        return 0;

    // re-use the same ev to save stack space
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    if (check_discard(ctx, ev, id))
        goto Done;

    push_exit_exec(ctx, *id, (file_info_t) {
        .inode = 0,
        .devmajor = 0,
        .devminor = 0,
    }, ev);

 Done:
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    return 0;
}

SEC("kretprobe/ret_sys_execve_4_8")
int kretprobe__ret_sys_execve_4_8(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (!id)
        return 0;

    // re-use the same ev to save stack space
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    if (check_discard(ctx, ev, id))
        goto Done;

    void *ptr = get_current_exe();
    if (!ptr)
        goto Done;

    push_exit_exec(ctx, *id, extract_file_info(ptr), ev);

Done:
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    return 0;
}

SEC("kretprobe/ret_sys_execveat_4_8")
int kretprobe__ret_sys_execveat_4_8(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (!id)
        return 0;

    // re-use the same ev to save stack space
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    if (check_discard(ctx, ev, id))
        goto Done;

    void *ptr = get_current_exe();
    if (!ptr)
        goto Done;

    void *path = offset_ptr(ptr, CRC_FILE_F_PATH);
    push_path(ctx, ev, path, RET_SYS_EXECVEAT_4_8, TE_EXEC_FILENAME_REV, *id);

    push_exit_exec(ctx, *id, extract_file_info(ptr), ev);

Done:
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    return 0;
}

static __always_inline int enter_clone(syscall_pattern_type_t sp, unsigned long flags,
                                       void __user *stack, int __user *parent_tid,
                                       int __user *child_tid, unsigned long tls,
                                       struct pt_regs *ctx, u32 ppid, u32 luid)
{
    // explicit memcpy to move the struct to the stack and satisfy the verifier
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;
    u64 id = bpf_get_prandom_u32();

    ev->id = id;
    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp, ppid, luid);
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

    bpf_map_update_elem(&process_ids, &pid_tgid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_clone(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };

    ev->id = *id;
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
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    ev->telemetry_type = TE_RETCODE;
    ev->u.r.retcode = (u32)PT_REGS_RC(ctx);
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
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;
    u64 id = bpf_get_prandom_u32();

    ev->id = id;
    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp, ppid, luid);
    push_telemetry_event(ctx, ev);

    pid_tgid = pid_tgid >> 32;
    bpf_map_update_elem(&process_ids, (u32 *)&pid_tgid, &id, BPF_ANY);

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
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };

    ev->id = *id;
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
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    ev->telemetry_type = TE_RETCODE;
    ev->u.r.retcode = (u32)PT_REGS_RC(ctx);
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
    GET_OFFSETS_4_8;
    return enter_clone3(SP_CLONE3, uargs, size, ctx, ppid, luid);
}

SEC("kretprobe/ret_sys_clone3")
int kretprobe__ret_sys_clone3(struct pt_regs *ctx)
{
    return exit_clone3(ctx);
}

// This probe can generically read the inode from a task_struct at any point
// where the first argument is a pointer to a task_struct, the event emit
// is a file type event with inode information, and a RETCODE with the correct
// PID, intended for use with tracing exec family calls.
SEC("kprobe/read_inode_task_struct")
int kprobe__read_inode_task_struct(struct pt_regs *ctx)
{
    // get new current
    void *ts = (void *)PT_REGS_PARM1(ctx);

    // get the true pid
    u32 pid = 0;
    u32 tgid = 0;
    read_value(ts, CRC_TASK_STRUCT_PID, &pid, sizeof(pid));
    read_value(ts, CRC_TASK_STRUCT_TGID, &tgid, sizeof(tgid));
    u64 pid_tgid = (u64)tgid << 32 | pid;

    // Get the inode number and device number
    u32 i_dev = 0;
    u64 i_ino = 0;
    void *ptr = NULL;
    void *sptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_MM, &ptr, sizeof(ptr));
    read_value(ptr, CRC_MM_STRUCT_EXE_FILE, &ptr, sizeof(ptr));
    read_value(ptr, CRC_FILE_F_INODE, &ptr, sizeof(ptr));
    read_value(ptr, CRC_INODE_I_SB, &sptr, sizeof(sptr));
    read_value(sptr, CRC_SBLOCK_S_DEV, &i_dev, sizeof(i_dev));
    read_value(ptr, CRC_INODE_I_INO, &i_ino, sizeof(i_ino));

    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);

    if (!id)
        return 0;

    // prepare event
    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };

    ev->id = *id;
    bpf_map_delete_elem(&process_ids, &pid_tgid);

    file_info_t fi = {
        .inode = i_ino,
        .devmajor = MAJOR(i_dev),
        .devminor = MINOR(i_dev),
    };

    bpf_get_current_comm(&fi.comm, sizeof(fi.comm));

    ev->telemetry_type = TE_FILE_INFO;
    __builtin_memcpy(&ev->u.file_info, &fi, sizeof(fi));
    push_telemetry_event(ctx, ev);

    // send retcode
    ev->id = *id;
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    ev->telemetry_type = TE_RETCODE;
    ev->u.r.retcode = (u32)PT_REGS_RC(ctx);
    ev->u.r.pid_tgid = pid_tgid;
    push_telemetry_event(ctx, ev);
    return 0;
}

// This probe can generically read the pid from a task_struct at any point
// where the first argument is a pointer to a task_struct, the event emit
// is a RETCODE with the correct PID, intended for use with tracing fork,
// clone, etc.
SEC("kprobe/read_pid_task_struct")
int kprobe__read_pid_task_struct(struct pt_regs *ctx)
{
    // get new current
    void *ts = (void *)PT_REGS_PARM1(ctx);

    // get the true pid
    u32 pid = 0;
    u32 tgid = 0;
    read_value(ts, CRC_TASK_STRUCT_PID, &pid, sizeof(pid));
    read_value(ts, CRC_TASK_STRUCT_TGID, &tgid, sizeof(tgid));
    u64 pid_tgid = (u64)tgid << 32 | pid;

    // get the real parent
    read_value(ts, CRC_TASK_STRUCT_REAL_PARENT, &ts, sizeof(ts));
    u32 ppid = 0;
    u32 ptgid = 0;

    // find ppid and ptid (offsets)
    // ts->real_parent->pid
    read_value(ts, CRC_TASK_STRUCT_PID, &ppid, sizeof(ppid));
    // ts->real_parent->tgid
    read_value(ts, CRC_TASK_STRUCT_TGID, &ptgid, sizeof(ptgid));

    // combine to find ID, get ID
    u64 ppid_tgid = (u64)ptgid << 32 | ppid;
    u64 *id = bpf_map_lookup_elem(&process_ids, &ppid_tgid);

    if (!id)
        return 0;

    // send event with ID
    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };

    ev->id = *id;
    bpf_map_delete_elem(&process_ids, &ppid_tgid);
    ev->telemetry_type = TE_RETCODE;
    ev->u.r.pid_tgid = pid_tgid;
    push_telemetry_event(ctx, ev);
    return 0;
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
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();

    ev->id = id;
    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp, ppid, luid);
    push_telemetry_event(ctx, ev);

    ev->id = id;
    ev->telemetry_type = TE_UNSHARE_FLAGS;
    ev->u.unshare_flags = flags;
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&process_ids, &pid_tgid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_unshare(struct pt_regs *ctx)
{

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);

    if (!id)
        goto Flush;

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = 0,
        .telemetry_type = 0,
        .u.v = {
            .value[0] = '\0',
            .truncated = FALSE,
        },
    };
    ev->id = *id;
    bpf_map_delete_elem(&process_ids, &pid_tgid);

    ev->telemetry_type = TE_RETCODE;
    ev->u.r.retcode = (u32)PT_REGS_RC(ctx);
    push_telemetry_event(ctx, ev);

Flush:
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
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;

    u64 id = bpf_get_prandom_u32();

    ev->id = id;
    FILL_TELEMETRY_SYSCALL_EVENT(ev, sp, ppid, luid);
    push_telemetry_event(ctx, ev);

    bpf_map_update_elem(&process_ids, &pid_tgid, &id, BPF_ANY);

    return 0;
}

static __always_inline int exit_exit(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);

    if (!id) {
        return 0;
    }

    ptelemetry_event_t ev = &(telemetry_event_t){
        .id = *id,
        .telemetry_type = TE_RETCODE,
        .u.r.retcode = (u32)PT_REGS_RC(ctx),
    };

    bpf_map_delete_elem(&process_ids, &pid_tgid);

    push_telemetry_event(ctx, ev);

    return 0;
}

// do_exit probes must call enter_exit() and exit_exit() since do_exit is __no_return
SEC("kprobe/do_exit_4_8")
int BPF_KPROBE_SYSCALL(kprobe__do_exit_4_8, int status)
{
    // if PID != TGID, then exit, we only care when the entire group exits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) ^ (pid_tgid & 0xFFFFFFFF))
        return 0;

    u32 ppid = -1;
    u32 luid = -1;
    GET_OFFSETS_4_8;
    if (enter_exit(SP_EXIT, status, ctx, ppid, luid) < 0)
        return 0;
    return exit_exit(ctx);
}

// do_exit probes must call enter_exit() and exit_exit() since do_exit is __no_return
SEC("kprobe/do_exit")
int BPF_KPROBE_SYSCALL(kprobe__do_exit, int status)
{
    // if PID != TGID, then exit, we only care when the entire group exits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) ^ (pid_tgid & 0xFFFFFFFF))
        return 0;
    if (enter_exit(SP_EXIT, status, ctx, -1, -1) < 0)
        return 0;
    return exit_exit(ctx);
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
    GET_OFFSETS_4_8;
    return enter_exit(SP_EXIT, status, ctx, ppid, luid);
}

SEC("kprobe/sys_exit")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit, int status)
{
    // if PID != TGID, then exit, we only care when the entire group exits
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((pid_tgid >> 32) ^ (pid_tgid & 0xFFFFFFFF))
        return 0;
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
