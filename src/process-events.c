// SPDX-License-Identifier: GPL-2.0+

#include <linux/kconfig.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>
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

// maximum size of each buffer (since they may have flexible arrays at
// the end)
#define MAX_PERCPU_BUFFER (1 << 15) // 32 KB

// TODO: make programs for newer kernels where we can use higher values

// maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 12

// maximum number of path segments that we can read from a
// d_path. This number is DELIBERATELY 16 * MAX_PATH_SEGMENTS_NOTAIL
// so as to not consume all the available tail calls on the path alone
// (max tail call is 33).
#define MAX_PATH_SEGMENTS_SKIP 192

// these structs are used to send data gathered/calculated in a kprobe
// to the kretprobe.

typedef struct {
    u64 pid_tgid;
    int unshare_flags;
} incomplete_unshare_t;

typedef struct {
    u64 pid_tgid;
    clone_info_t clone_info;
} incomplete_clone_t;

// used for events with flexible sizes (i.e., exec*) so it can send
// extra data. Used in conjuction with a map such that it does not use
// the stack size limit.
typedef struct
{
    char buf[MAX_PERCPU_BUFFER];
} buf_t;

struct bpf_map_def SEC("maps/mount_events") mount_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

// A per cpu cache of dentry so we can hold it across tail calls.
struct bpf_map_def SEC("maps/percpu_dentries") percpu_dentries = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(void *),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

// The map where process event messages get emitted to
struct bpf_map_def SEC("maps/process_events") process_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

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

// A map of what pids have started an exec; with the value pointing to
// what thread started it.
struct bpf_map_def SEC("maps/exec_tids") exec_tids = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),   // pid
    .value_size = sizeof(u32), // tid
    .max_entries = 8 * 1024,
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

// A per cpu buffer that can hold more data than allowed in the
// stack. Used to collect data of variable length such as a string.
struct bpf_map_def SEC("maps/buffers") buffers = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(buf_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

#define load_event(map, key, ty)                            \
    void *__eventp = bpf_map_lookup_elem(&map, &key);       \
    if (__eventp == NULL) goto NoEvent;                     \
    ty event = {0};                                         \
    __builtin_memcpy(&event, (void *)__eventp, sizeof(ty)); \
    if (event.pid_tgid != key) goto EventMismatch;

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

// writes '\0' into the buffer; checks and updates the offset
static __always_inline void write_null_char(buf_t *buffer)
{
    process_message_t *pm = (process_message_t *)buffer;
    u32 *offset = &pm->u.syscall_info.data.exec_info.buffer_length;

    // bpf_probe_read_str always write a null character at the end,
    // even when truncating. So this is either adding a null at the
    // end or replacing a null with another null when full which is OK.
    buffer->buf[*offset & (MAX_PERCPU_BUFFER - 1)] = '\0';
    *offset = *offset + 1;
}

// returns NULL if offsets have not yet been loaded
static __always_inline void *offset_loaded()
{
    u64 offset = CRC_LOADED;
    return bpf_map_lookup_elem(&offsets, &offset);
}

// accepts a pointer a `task_struct`. Returns NULL if the task_struct
// belongs to a kernel process
static __always_inline void *is_user_process(void *ts)
{
    void *mmptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_MM, &mmptr, sizeof(mmptr));
    return mmptr;
}

// pushes a message to the process_events perfmap for the current
// CPU.
static __always_inline int push_message(struct pt_regs *ctx, pprocess_message_t ev)
{
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
}

// pushes a message with an extra `dynamic_size` number of bytes. It
// caps the message to `MAX_PERCPU_BUFFER - 1` to appease verifier
// however. The "-1" is there to make it an easy bit cap against a
// power of two; it may drop an null byte out of the string which is
// OK.
static __always_inline int push_flexible_message(struct pt_regs *ctx, pprocess_message_t ev, u64 dynamic_size)
{
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, dynamic_size & (MAX_PERCPU_BUFFER - 1));
}

// writes the string into the provided buffer. On a
// succesful write it modifies the offset with the length of the read
// string. It deliberately does not handle truncations; it just reads
// up to `max_string`.
static __always_inline int write_string(const char *string, buf_t *buffer, const u32 max_string)
{
    // A smarter implementation of this wouldn't use max_string but
    // instead would just check MAX_PERCPU_BUFFER - *offset as the max
    // that it can write. However, the verifier seems allergic to an
    // smarter implementation as it complains about potential out of
    // bounds or negative values. While perhaps theoretically possible
    // to improve this with just the right incantations (and maybe
    // turning off some compiler optimizaitons that remove some
    // checks) at this time this is considered good enough (TM).

    process_message_t *pm = (process_message_t *)buffer;
    u32 *offset = &pm->u.syscall_info.data.exec_info.buffer_length;

    // already too full
    if (*offset > MAX_PERCPU_BUFFER - max_string)
        return -PMW_BUFFER_FULL;

    int sz = bpf_probe_read_str(&buffer->buf[*offset], max_string, string);
    if (sz < 0)
    {
        return -PMW_UNEXPECTED;
    }
    else
    {
        *offset = *offset + sz;
        return sz;
    }
}

// fills the syscall_info with all the common values. Returns 1 if the
// task struct is not a user process or if the offsets have not yet
// been loaded.
static __always_inline int fill_syscall(syscall_info_t *syscall_info, void *ts, u32 pid)
{
    if (!offset_loaded())
        return 1;
    if (!is_user_process(ts))
        return 1;

    void *ptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_REAL_PARENT, &ptr, sizeof(ptr));

    u32 ppid = -1;
    read_value(ptr, CRC_TASK_STRUCT_TGID, &ppid, sizeof(ppid));

    u32 luid = -1;
    read_value(ts, CRC_TASK_STRUCT_LOGINUID, &luid, sizeof(luid));

    u64 uid_gid = bpf_get_current_uid_gid();

    syscall_info->pid = pid;
    syscall_info->ppid = ppid;
    syscall_info->luid = luid;
    syscall_info->euid = uid_gid >> 32;
    syscall_info->egid = uid_gid & 0xFFFFFFFF;
    syscall_info->mono_ns = bpf_ktime_get_ns();

    return 0;
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

    file_info_t file_info = {
        .inode = i_ino,
        .devmajor = MAJOR(i_dev),
        .devminor = MINOR(i_dev),
    };

    bpf_get_current_comm(&file_info.comm, sizeof(file_info.comm));

    return file_info;
}

// writes a d_path into a buffer - tail calling if necessary
static __always_inline int write_path(struct pt_regs *ctx, void **dentry, buf_t *buffer,
                                      tail_call_slot_t tail_call, error_info_t *einfo)
{
    // any early exit at the start is unexpected
    int ret = -PMW_READING_FIELD;

    void *offset = NULL;
    u64 offset_key = 0;

    einfo->offset_crc = CRC_DENTRY_D_NAME;
    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 name = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    einfo->offset_crc = CRC_QSTR_NAME;
    SET_OFFSET(CRC_QSTR_NAME);
    name = name + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    einfo->offset_crc = CRC_DENTRY_D_PARENT;
    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset; // offset of d_parent

    // at this point let's assume success
    einfo->offset_crc = 0;
    ret = 0;

// Anything we add to this for-loop will be repeated
// MAX_PATH_SEGMENTS_NOTAIL so be very careful of going over the max
// instruction limit (4096).
#pragma unroll MAX_PATH_SEGMENTS_NOTAIL
    for (int i = 0; i < MAX_PATH_SEGMENTS_NOTAIL; i++)
    {
        if (bpf_probe_read(&offset, sizeof(offset), *dentry + name) < 0)
            goto Skip;

        // NAME_MAX doesn't include null character; so +1 to take it
        // into account. Not all systems enforce NAME_MAX so
        // truncation may happen per path segment. TODO: emit
        // truncation metrics to see if we need to care about this.
        int sz = write_string((char *)offset, buffer, NAME_MAX + 1);
        if (sz < 0)
        {
            if (sz == -PMW_UNEXPECTED)
            {
                ret = -PMW_READ_PATH_STRING;
            }
            else
            {
                ret = sz;
            }
            goto Skip;
        }

        // get the parent
        void *old_dentry = *dentry;
        bpf_probe_read(dentry, sizeof(*dentry), *dentry + parent);

        // there is no parent or parent points to itself
        if ((*dentry) == NULL || old_dentry == *dentry)
            goto Skip;
    }

    bpf_tail_call(ctx, &tail_call_table, tail_call);

    ret = -PMW_TAIL_CALL_MAX;
    einfo->tailcall = tail_call;

Skip:
    return ret;
}

static __always_inline void exit_exec(struct pt_regs *ctx, process_message_type_t pm_type,
                                      tail_call_slot_t tail_call)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    void **dentry = (void **)bpf_map_lookup_elem(&percpu_dentries, &key);
    if (dentry == NULL) return;

    process_message_t *pm = (process_message_t *)buffer;
    int ret = 0;

    // We have been tail-called to find the exename, so go straight to
    // ExeName
    if ((*dentry) != NULL) goto ExeName;

    /* SANITY CHECKS THAT THE EVENT IS RELEVANT */

    // do not emit failed execs
    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) goto Done;

    void *ts = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // do not emit if we couldn't fill the syscall info
    if (fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32) != 0) goto Done;

    void *mmptr = is_user_process(ts);
    if (mmptr == NULL) goto Done; // this is OK; it just means not a user process

    void *exe = NULL;
    read_value(mmptr, CRC_MM_STRUCT_EXE_FILE, &exe, sizeof(exe));
    if (!exe) // this is wholly unexpected so emit a warning
    {
        ret = -PMW_MISSING_EXE;
        goto Done;
    }

    u64 arg_start = 0;
    u64 arg_end = 0;
    read_value(mmptr, CRC_MM_STRUCT_ARG_START, &arg_start, sizeof(arg_start));
    read_value(mmptr, CRC_MM_STRUCT_ARG_END, &arg_end, sizeof(arg_end));
    if (arg_end < arg_start) {
        ret = -PMW_ARGV_INCONSISTENT;
        pm->u.warning_info.info.argv.start = arg_start;
        pm->u.warning_info.info.argv.end = arg_end;
        goto Done;
    }

    /* DONE WITH SANITY CHECKS - TIME TO FILL UP `pm` */

    pm->type = pm_type;
    pm->u.syscall_info.retcode = retcode;
    pm->u.syscall_info.data.exec_info.file_info = extract_file_info(exe);

    /* SAVE ARGV */

    // length of all strings counting NULLs
    u64 argv_length = arg_end - arg_start;

    // manually truncate the length to half of the buffer so the ebpf
    // verifier knows for a fact we are not going over the bounds of
    // our buffer.
    const u64 MAX_ARGV_LENGTH = (MAX_PERCPU_BUFFER >> 1) - 1;
    pm->u.syscall_info.data.exec_info.argv_truncated = (u8) (argv_length > MAX_ARGV_LENGTH);
    argv_length = (arg_end - arg_start) & (MAX_ARGV_LENGTH);

    u32 offset = sizeof(process_message_t);
    pm->u.syscall_info.data.exec_info.buffer_length = offset;
    if (bpf_probe_read(&buffer->buf[offset], argv_length, (void *)arg_start) < 0) {
        ret = -PMW_UNEXPECTED;
        goto Done;
    }

    pm->u.syscall_info.data.exec_info.buffer_length += argv_length;

    // if for any reason the last character is not a NULL (e.g., we
    // truncated the argv not at a string boundary) make sure to
    // append a NULL to terminate the string
    if (buffer->buf[(pm->u.syscall_info.data.exec_info.buffer_length - 1) & (MAX_PERCPU_BUFFER - 1)] != '\0') {
        argv_length += 1; // we are taking up one more than we thought
        write_null_char(buffer);
    }

    // do not rely on double NULL to separate argv from the rest. An
    // empty argument can also cause a double NULL.
    pm->u.syscall_info.data.exec_info.argv_length = argv_length;

    // append a NULL to signify the end of the argv
    // strings. Technically not necessary since we are passing
    // `argv_length` but it keeps it consistent with the other strings
    // in the buffer
    write_null_char(buffer);

    /* FIND THE TOP DENTRY TO THE EXE */

    void *path = offset_ptr(exe, CRC_FILE_F_PATH);
    // TODO: grab the mount that wraps path->mnt to find the real mount point
    if (read_value(path, CRC_PATH_DENTRY, dentry, sizeof(*dentry)) < 0)
    {
        ret = -PMW_READING_FIELD;
        pm->u.warning_info.info.offset_crc = CRC_PATH_DENTRY;
        goto Done;
    }

ExeName:;
    /* WRITE EXE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, dentry, buffer, tail_call, &pm->u.warning_info.info);

    // reset skips back to 0. This will automatically update it in the
    // map so no need to do a bpf_map_update_elem.
    *dentry = NULL;
    if (ret < 0) goto Done;

    // add an extra null byte to signify string section end
    write_null_char(buffer);

    /* PROCESS PWD IN A TAIL CALL  */
    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_PWD);

    // if we fail to tail call we still got quite a bit of information
    // so let's push what we have
    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

    // but still emit a warning afterwards
    ret = -PMW_TAIL_CALL_MAX;
    pm->u.warning_info.info.tailcall = SYS_EXEC_PWD;

Done:;
    if (ret < 0)
    {
        pm->type = PM_WARNING;
        pm->u.warning_info.pid_tgid = bpf_get_current_pid_tgid();
        pm->u.warning_info.message_type = pm_type;
        pm->u.warning_info.code = -ret;

        push_message(ctx, pm);
    }

    return;
}

SEC("kprobe/sys_exec_pwd")
int kprobe__sys_exec_pwd(struct pt_regs *ctx)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */

    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return 0;

    void **dentry = (void **)bpf_map_lookup_elem(&percpu_dentries, &key);
    if (dentry == NULL) return 0;

    // create a separate einfo so we do not override the data in the
    // buffer during warnings as we may still want to emit the event
    // with partial data.
    error_info_t einfo = {0};
    int ret = 0;
    process_message_t *pm = (process_message_t *)buffer;
    process_message_type_t pm_type = pm->type;

    if ((*dentry) != NULL) goto Pwd;

    /* FIND THE TOP DENTRY TO THE PWD */

    void *ts = (void *)bpf_get_current_task();
    void *path_ptr = NULL;
    ret = -PMW_READING_FIELD;

    // task_struct->fs
    if (read_value(ts, CRC_TASK_STRUCT_FS, &path_ptr, sizeof(path_ptr)) < 0)
    {
        einfo.offset_crc = CRC_TASK_STRUCT_FS;
        goto Done;
    }

    // &(task_struct->fs->pwd)
    path_ptr = offset_ptr(path_ptr, CRC_FS_STRUCT_PWD);
    if (path_ptr == NULL)
    {
        einfo.offset_crc = CRC_TASK_STRUCT_FS;
        goto Done;
    }

    // TODO: grab the mount that wraps pwd->mnt to find the real mount point
    // task_struct->fs->pwd.dentry
    if (read_value(path_ptr, CRC_PATH_DENTRY, dentry, sizeof(*dentry)) < 0)
    {
        einfo.offset_crc = CRC_PATH_DENTRY;
        goto Done;
    }

 Pwd:;
    /* WRITE PATH; IT MAY TAIL CALL */

    ret = write_path(ctx, dentry, buffer, SYS_EXEC_PWD, &einfo);

 Done:;
    /* PUSH THE EVENT AND RESET */
    *dentry = NULL;

    // add an extra null byte to signify string section end
    write_null_char(buffer);
    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

    if (ret < 0) {
        pm->type = PM_WARNING;
        pm->u.warning_info.pid_tgid = bpf_get_current_pid_tgid();
        pm->u.warning_info.message_type = pm_type;
        pm->u.warning_info.code = -ret;
        pm->u.warning_info.info = einfo;
        push_message(ctx, pm);
    }

    return 0;
}

SEC("kretprobe/ret_sys_execve_4_8")
int kretprobe__ret_sys_execve_4_8(struct pt_regs *ctx)
{
    exit_exec(ctx, PM_EXECVE, RET_SYS_EXECVE_4_8);

    return 0;
}

SEC("kretprobe/ret_sys_execveat_4_8")
int kretprobe__ret_sys_execveat_4_8(struct pt_regs *ctx)
{
    exit_exec(ctx, PM_EXECVEAT, RET_SYS_EXECVEAT_4_8);

    return 0;
}

static __always_inline void enter_clone(struct pt_regs *ctx, process_message_type_t pm_type, unsigned long flags)
{
    // we do not care about threads spawning; ignore clones that would
    // share the same thread group as the parent.
    if (flags & CLONE_THREAD)
        return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_clone_t event = {0};
    event.pid_tgid = pid_tgid;
    event.clone_info.flags = flags;

    int ret = bpf_map_update_elem(&incomplete_clones, &pid_tgid, &event, BPF_ANY);
    if (ret < 0)
    {
        process_message_t pm = {0};
        pm.type = PM_WARNING;
        pm.u.warning_info.pid_tgid = pid_tgid;
        pm.u.warning_info.message_type = pm_type;
        pm.u.warning_info.code = PMW_UPDATE_MAP_ERROR;
        pm.u.warning_info.info.err = ret;

        push_message(ctx, &pm);

        return;
    }

    return;
}

// handles the kretprobe of clone-like syscalls (fork, vfork, clone, clone3)
static __always_inline void exit_clonex(struct pt_regs *ctx, pprocess_message_t pm, process_message_type_t pm_type)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_clones, pid_tgid, incomplete_clone_t);

    int retcode = PT_REGS_RC(ctx);
    if (retcode < 0)
        goto Done;

    void *ts = (void *)bpf_get_current_task();
    if (fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32) != 0)
        goto Done;

    pm->type = pm_type;
    pm->u.syscall_info.data.clone_info = event.clone_info;
    pm->u.syscall_info.retcode = retcode;

    push_message(ctx, pm);

    goto Done;

 EventMismatch:;
    pm->type = PM_WARNING;
    pm->u.warning_info.pid_tgid = pid_tgid;
    pm->u.warning_info.message_type = pm_type;
    pm->u.warning_info.code = PMW_PID_TGID_MISMATCH;
    pm->u.warning_info.info.stored_pid_tgid = event.pid_tgid;

    push_message(ctx, pm);

 Done:;
    // only delete at the every end so the event pointer above is
    // valid for the duration of this function.
    bpf_map_delete_elem(&incomplete_clones, &pid_tgid);
    return;

 NoEvent:;
    return;
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
    enter_clone(ctx, PM_CLONE, flags);

    return 0;
}

SEC("kprobe/sys_clone3")
int BPF_KPROBE_SYSCALL(kprobe__sys_clone3, struct clone_args __user *uargs, size_t size)
{
    u64 flags = 0;
    bpf_probe_read(&flags, sizeof(u64), &uargs->flags);

    enter_clone(ctx, PM_CLONE3, flags);

    return 0;
}

SEC("kretprobe/ret_sys_clone3")
int kretprobe__ret_sys_clone3(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clonex(ctx, &sev, PM_CLONE3);
    return 0;
}

// This probe can generically read the pid from a task_struct at any
// point where the first argument is a pointer to a task_struct, the
// event emit is a RETCODE with the correct PID, intended for use with
// tracing fork, clone, etc. It returns early if the task is not a
// main thread (pid != tid).
SEC("kprobe/read_pid_task_struct")
int kprobe__read_pid_task_struct(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_clones, pid_tgid, incomplete_clone_t);

    // get passed in task_struct
    void *ts = (void *)PT_REGS_PARM1(ctx);

    // get the true pid
    u32 npid = 0;
    u32 ntgid = 0;
    read_value(ts, CRC_TASK_STRUCT_PID, &npid, sizeof(npid));
    read_value(ts, CRC_TASK_STRUCT_TGID, &ntgid, sizeof(ntgid));

    // this means that this task_struct belongs to a non-main
    // thread. We do not care about new threads being spawned so exit
    // early.
    if (npid != ntgid)
    {
        // the kretprobe shouldn't care about it either
        bpf_map_delete_elem(&incomplete_clones, &pid_tgid);
        return 0;
    }

    // deliberately not deleting from the map - we'll let the
    // kretprobe do that and send the event
    event.clone_info.child_pid = ntgid;
    // we copied the event so we need to manually update it
    bpf_map_update_elem(&incomplete_clones, &pid_tgid, &event, BPF_ANY);

    return 0;

 EventMismatch:;
    // let the kretprobe return the error as that has more information
    return 0;

 NoEvent:;
    return 0;
}

SEC("kprobe/sys_fork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_fork_4_8)
{
    enter_clone(ctx, PM_FORK, SIGCHLD);

    return 0;
}

SEC("kprobe/sys_vfork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_vfork_4_8)
{
    enter_clone(ctx, PM_VFORK, CLONE_VFORK | CLONE_VM | SIGCHLD);

    return 0;
}

SEC("kretprobe/ret_sys_clone")
int kretprobe__ret_sys_clone(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clonex(ctx, &sev, PM_CLONE);
    return 0;
}

SEC("kretprobe/ret_sys_fork")
int kretprobe__ret_sys_fork(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clonex(ctx, &sev, PM_FORK);
    return 0;
}

SEC("kretprobe/ret_sys_vfork")
int kretprobe__ret_sys_vfork(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clonex(ctx, &sev, PM_VFORK);
    return 0;
}

SEC("kprobe/sys_unshare_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_unshare_4_8, int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_unshare_t event = {0};
    event.pid_tgid = pid_tgid;
    event.unshare_flags = flags;

    int ret = bpf_map_update_elem(&incomplete_unshares, &pid_tgid, &event, BPF_ANY);
    if (ret < 0)
    {
        process_message_t pm = {0};
        pm.type = PM_WARNING;
        pm.u.warning_info.pid_tgid = pid_tgid;
        pm.u.warning_info.message_type = PM_UNSHARE;
        pm.u.warning_info.code = PMW_UPDATE_MAP_ERROR;
        pm.u.warning_info.info.err = ret;

        push_message(ctx, &pm);

        return 0;
    }

    return 0;
}

SEC("kretprobe/ret_sys_unshare")
int kretprobe__ret_sys_unshare(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    process_message_t pm = {0};
    load_event(incomplete_unshares, pid_tgid, incomplete_unshare_t);

    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0)
        goto Done;

    void *ts = (void *)bpf_get_current_task();

    if (fill_syscall(&pm.u.syscall_info, ts, pid_tgid >> 32) != 0)
        goto Done;

    pm.type = PM_UNSHARE;
    pm.u.syscall_info.data.unshare_flags = event.unshare_flags;
    pm.u.syscall_info.retcode = retcode;

    push_message(ctx, &pm);
    goto Done;

 EventMismatch:;
    pm.type = PM_WARNING;
    pm.u.warning_info.pid_tgid = pid_tgid;
    pm.u.warning_info.code = PMW_PID_TGID_MISMATCH;
    pm.u.warning_info.info.stored_pid_tgid = event.pid_tgid;
    push_message(ctx, &pm);

 Done:;
    // only delete at the very end so the event pointer above is valid
    // for the duration of this function.
    bpf_map_delete_elem(&incomplete_unshares, &pid_tgid);
    return 0;

 NoEvent:;
    return 0;
}

static __always_inline void push_exit(struct pt_regs *ctx, pprocess_message_t ev,
                                      process_message_type_t pm_type, u32 pid)
{
    void *ts = (void *)bpf_get_current_task();
    if (fill_syscall(&ev->u.syscall_info, ts, pid) != 0)
        return;
    ev->type = pm_type;

    push_message(ctx, ev);
}

SEC("kprobe/sys_exit")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit, int status)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;

    // exit of a non-main thread
    if ((pid) ^ (tid))
        return 0;

    process_message_t sev = {0};
    push_exit(ctx, &sev, PM_EXIT, pid);

    return 0;
}

SEC("kprobe/sys_exit_group")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_group, int status)
{
    process_message_t sev = {0};
    push_exit(ctx, &sev, PM_EXITGROUP, bpf_get_current_pid_tgid() >> 32);

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
