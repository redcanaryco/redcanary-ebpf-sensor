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
#include "process/unshare.h"
#include "process/helpers.h"
#include "process/clone.h"

// maximum size of each buffer (since they may have flexible arrays at
// the end)
#define MAX_PERCPU_BUFFER (1 << 15) // 32 KB

// TODO: make programs for newer kernels where we can use higher values

// maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 32

// used for events with flexible sizes (i.e., exec*) so it can send
// extra data. Used in conjuction with a map such that it does not use
// the stack size limit.
typedef struct
{
    char buf[MAX_PERCPU_BUFFER];
} buf_t;

typedef struct
{
    // the dentry to the next path segment
    void *next_dentry;
    // the virtual fs mount where the path is mounted
    void *vfsmount;
} cached_path_t;

struct bpf_map_def SEC("maps/mount_events") mount_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

// A per cpu cache of dentry so we can hold it across tail calls.
struct bpf_map_def SEC("maps/percpu_path") percpu_path = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(cached_path_t),
    .max_entries = 1,
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

static __always_inline void init_cached_path(cached_path_t *cached_path, void *path)
{
    // cached_path->next_dentry = path->dentry;
    cached_path->next_dentry = read_field_ptr(path, CRC_PATH_DENTRY);

    // cached_path->vfsmount = path->mnt;
    cached_path->vfsmount = read_field_ptr(path, CRC_PATH_MNT);
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

// writes '\0' into the buffer; checks and updates the offset
static __always_inline void write_null_char(buf_t *buffer)
{
    process_message_t *pm = (process_message_t *)buffer;
    u32 *offset = &pm->u.syscall_info.data.exec_info.buffer_length;

    // We are already full and we do not want the bitwise AND to
    // modulus back onto 0 and overwrite the first bit so just
    // bail. Best case this is the last NULL to write so we are done
    // anyway, worst case there are more strings to write and it will
    // trigger a buffer full warning later.
    if (*offset == MAX_PERCPU_BUFFER) return;

    // `&` safe because we've checked that offset isn't going to
    // "overflow".
    buffer->buf[*offset & (MAX_PERCPU_BUFFER - 1)] = '\0';
    *offset = *offset + 1;
}

// pushes a message with an extra `dynamic_size` number of bytes. It
// will never send more than `MAX_PERCPU_BUFFER` number of bytes. It
// is a *bug* if dynamic_size here is larger than MAX_PERCPU_BUFFER
// and it will cause the number of bytes to to dynamic_size %
// MAX_PERCPU_BUFFER.
static __always_inline int push_flexible_message(struct pt_regs *ctx, pprocess_message_t ev, u64 dynamic_size)
{
    // The -1 and +1 logic is here to prevent a buffer that is exactly
    // MAX_PERCPU_BUFFER size to become 0 due to the bitwise AND. We
    // know that dynamic_size will never be 0 so this is safe.
    u64 size_to_send = ((dynamic_size - 1) & (MAX_PERCPU_BUFFER - 1)) + 1;
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, size_to_send);
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

// it's argument should be a pointer to a file
static __always_inline int extract_file_info(void *ptr, file_info_t *file_info)
{
    void *f_inode = read_field_ptr(ptr, CRC_FILE_F_INODE);
    if (f_inode == NULL) return -1;

    void *i_sb = read_field_ptr(f_inode, CRC_INODE_I_SB);
    if (i_sb == NULL) return -1;

    // inode
    if (read_field(f_inode, CRC_INODE_I_INO, &file_info->inode, sizeof(file_info->inode)) < 0)
        return -1;

    // device major/minor
    u32 i_dev = 0;
    if (read_field(i_sb, CRC_SBLOCK_S_DEV, &i_dev, sizeof(i_dev)) < 0) return -1;

    file_info->devmajor = MAJOR(i_dev);
    file_info->devminor = MINOR(i_dev);

    // TODO: handle error
    // comm
    bpf_get_current_comm(&file_info->comm, sizeof(file_info->comm));

    return 0;
}

// writes a d_path into a buffer - tail calling if necessary
static __always_inline int write_path(struct pt_regs *ctx, cached_path_t *cached_path, buf_t *buffer,
                                      tail_call_slot_t tail_call)
{
    u32 *offset = get_offset(CRC_DENTRY_D_NAME);
    if (offset == NULL) return -1;
    u32 name = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    offset = get_offset(CRC_QSTR_NAME);
    if (offset == NULL) return -1;
    name = name + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    offset = get_offset(CRC_DENTRY_D_PARENT);
    if (offset == NULL) return -1;
    u32 dentry_parent = *(u32 *)offset; // offset of d_parent

    offset = get_offset(CRC_MOUNT_MNTPARENT);
    if (offset == NULL) return -1;
    u32 mnt_parent_offset = *(u32 *)offset; // offset of mount->mnt_parent

    offset = get_offset(CRC_VFSMOUNT_MNTROOT);
    if (offset == NULL) return -1;
    u32 mnt_root_offset = *(u32 *)offset; // offset of vfsmount->mnt_root

    offset = get_offset(CRC_MOUNT_MOUNTPOINT);
    if (offset == NULL) return -1;
    u32 mountpoint_offset = *(u32 *)offset; // offset of mount->mountpoint

    offset = get_offset(CRC_MOUNT_MNT);
    if (offset == NULL) return -1;
    u32 mnt_offset = *(u32 *)offset; // offset of mount->mnt

    void *mnt = cached_path->vfsmount - mnt_offset;
    void *mnt_parent = NULL;
    void *mnt_root = NULL;

    bpf_probe_read(&mnt_parent, sizeof(mnt_parent), mnt + mnt_parent_offset);
    bpf_probe_read(&mnt_root, sizeof(mnt_root), cached_path->vfsmount + mnt_root_offset);

    int ret = 0;

// Anything we add to this for-loop will be repeated
// MAX_PATH_SEGMENTS_NOTAIL so be very careful of going over the max
// instruction limit (4096).
#pragma unroll MAX_PATH_SEGMENTS_NOTAIL
    for (int i = 0; i < MAX_PATH_SEGMENTS_NOTAIL; i++)
    {
        if (cached_path->next_dentry == mnt_root)
        {
            if (mnt == mnt_parent) goto AtGlobalRoot;

            // we are done with the path but not with its mount
            // start appending the path to the mountpoint
            bpf_probe_read(&cached_path->next_dentry, sizeof(cached_path->next_dentry), mnt + mountpoint_offset);

            // allow for nested mounts
            mnt = mnt_parent;
            bpf_probe_read(&mnt_parent, sizeof(mnt_parent), mnt + mnt_parent_offset);

            // set what our new mount root is
            cached_path->vfsmount = mnt + mnt_offset;
            bpf_probe_read(&mnt_root, sizeof(mnt_root), cached_path->vfsmount + mnt_root_offset);

            // force a continue early to check if the new path is also at at its root
            continue;
        }

        void *dentry = cached_path->next_dentry;
        bpf_probe_read(&cached_path->next_dentry, sizeof(cached_path->next_dentry), cached_path->next_dentry + dentry_parent);

        if (dentry == cached_path->next_dentry) goto AtGlobalRoot;

        if (bpf_probe_read(&offset, sizeof(offset), dentry + name) < 0)
            goto NameError;

        // NAME_MAX doesn't include null character; so +1 to take it
        // into account. Not all systems enforce NAME_MAX so
        // truncation may happen per path segment. TODO: emit
        // truncation metrics to see if we need to care about this.
        ret = write_string((char *)offset, buffer, NAME_MAX + 1);
        if (ret < 0) goto WriteError;
    }

    bpf_tail_call(ctx, &tail_call_table, tail_call);

    error_info_t info = {0};
    info.tailcall = tail_call;
    set_local_warning(PMW_TAIL_CALL_MAX, info);

    return -1;

 AtGlobalRoot:;
    // let's not forget to write the global root (might be a / or the memfd name)
    if (bpf_probe_read(&offset, sizeof(offset), cached_path->next_dentry + name) < 0)
            goto NameError;

    ret = write_string((char *)offset, buffer, NAME_MAX + 1);
    if (ret < 0) goto WriteError;

    return 0;

 WriteError:;
    error_info_t empty_info = {0};
    if (ret == -PMW_UNEXPECTED) {
        set_local_warning(PMW_READ_PATH_STRING, empty_info);
    } else {
        set_local_warning(-ret, empty_info);
    }

    return -1;

 NameError:;
    error_info_t read_error_info = {0};
    read_error_info.offset_crc = CRC_QSTR_NAME;
    set_local_warning(PMW_PTR_FIELD_READ, read_error_info);

    return -1;
}

static __always_inline void exit_exec(struct pt_regs *ctx, process_message_type_t pm_type,
                                      tail_call_slot_t tail_call)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    process_message_t *pm = (process_message_t *)buffer;
    int ret = 0;

    // We have been tail-called to find the exename, so go straight to
    // ExeName
    if (cached_path->next_dentry != NULL) goto ExeName;

    /* SANITY CHECKS THAT THE EVENT IS RELEVANT */

    // do not emit failed execs
    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) return;

    void *ts = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // do not emit if we couldn't fill the syscall info
    ret = fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32);
    if (ret > 0) return;
    if (ret < 0) goto EmitWarning;

    void *mmptr = read_field_ptr(ts, CRC_TASK_STRUCT_MM);
    // we already checked that it is a user process in fill_syscall so
    // this should never be NULL
    if (mmptr == NULL) goto EmitWarning;

    void *exe = read_field_ptr(mmptr, CRC_MM_STRUCT_EXE_FILE);
    if (exe == NULL) goto EmitWarning;

    u64 arg_start = 0;
    if (read_field(mmptr, CRC_MM_STRUCT_ARG_START, &arg_start, sizeof(arg_start)) < 0)
        goto EmitWarning;

    u64 arg_end = 0;
    if (read_field(mmptr, CRC_MM_STRUCT_ARG_END, &arg_end, sizeof(arg_end)))
        goto EmitWarning;

    if (arg_end < arg_start) {
        error_info_t info = {0};
        info.argv.start = arg_start;
        info.argv.end = arg_end;
        set_local_warning(PMW_ARGV_INCONSISTENT, info);

        goto EmitWarning;
    }

    /* DONE WITH SANITY CHECKS - TIME TO FILL UP `pm` */

    pm->type = pm_type;
    pm->u.syscall_info.retcode = retcode;
    if (extract_file_info(exe, &pm->u.syscall_info.data.exec_info.file_info) < 0) goto EmitWarning;

    /* SAVE ARGV */

    // length of all strings counting NULLs
    u64 argv_length = arg_end - arg_start;

    // manually truncate the length to half of the buffer so the ebpf
    // verifier knows for a fact we are not going over the bounds of
    // our buffer.
    const u64 MAX_ARGV_LENGTH = (MAX_PERCPU_BUFFER >> 1) - 1;
    if (argv_length > MAX_ARGV_LENGTH) {
        pm->u.syscall_info.data.exec_info.argv_truncated = 1;
        argv_length = MAX_ARGV_LENGTH;
    } else {
        pm->u.syscall_info.data.exec_info.argv_truncated = 0;
    }

    u32 offset = sizeof(process_message_t);
    pm->u.syscall_info.data.exec_info.buffer_length = offset;
    if (bpf_probe_read(&buffer->buf[offset], argv_length, (void *)arg_start) < 0) {
        error_info_t info = {0};
        info.argv.start = arg_start;
        info.argv.end = arg_end;
        set_local_warning(PMW_READ_ARGV, info);
        goto EmitWarning;
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
    void *path = ptr_to_field(exe, CRC_FILE_F_PATH);
    if (path == NULL) goto EmitWarning;

    init_cached_path(cached_path, path);
    if (cached_path->next_dentry == NULL || cached_path->vfsmount == NULL) goto EmitWarning;

 ExeName:;
    /* WRITE EXE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, cached_path, buffer, tail_call);

    // reset skips back to 0. This will automatically update it in the
    // map so no need to do a bpf_map_update_elem.
    cached_path->next_dentry = NULL;
    if (ret < 0) goto EmitWarning;

    // add an extra null byte to signify string section end
    write_null_char(buffer);

    /* PROCESS PWD IN A TAIL CALL  */
    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_PWD);

    // if we fail to tail call we still got quite a bit of information
    // so let's push what we have
    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

    // but still emit a warning afterwards
    error_info_t info = {0};
    info.tailcall = tail_call;
    set_local_warning(PMW_TAIL_CALL_MAX, info);

 EmitWarning:;
    cached_path->next_dentry = NULL;

    push_warning(ctx, pm, pm_type);
}

SEC("kprobe/sys_exec_pwd")
int kprobe__sys_exec_pwd(struct pt_regs *ctx)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */

    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return 0;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return 0;

    int ret = 0;
    process_message_t *pm = (process_message_t *)buffer;
    process_message_type_t pm_type = pm->type;

    if (cached_path->next_dentry != NULL) goto Pwd;

    /* FIND THE TOP DENTRY TO THE PWD */

    void *ts = (void *)bpf_get_current_task();

    // set ret to error to handle any going to Done early
    ret = -1;
    // task_struct->fs
    void *path = path = read_field_ptr(ts, CRC_TASK_STRUCT_FS);
    if (path == NULL) goto Done;

    // &(task_struct->fs->pwd)
    path = ptr_to_field(path, CRC_FS_STRUCT_PWD);
    if (path == NULL) goto Done;

    init_cached_path(cached_path, path);
    if (cached_path->next_dentry == NULL || cached_path->vfsmount == NULL) goto Done;

 Pwd:;
    /* WRITE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, cached_path, buffer, SYS_EXEC_PWD);

 Done:;
    /* PUSH THE EVENT AND RESET */
    cached_path->next_dentry = NULL;

    // add an extra null byte to signify string section end
    write_null_char(buffer);
    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

    if (ret < 0) push_warning(ctx, pm, pm_type);

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
    exit_clone(ctx, &sev, PM_CLONE3);
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
    // get passed in task_struct
    void *ts = (void *)PT_REGS_PARM1(ctx);
    add_childpid(ts);

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
    exit_clone(ctx, &sev, PM_CLONE);
    return 0;
}

SEC("kretprobe/ret_sys_fork")
int kretprobe__ret_sys_fork(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clone(ctx, &sev, PM_FORK);
    return 0;
}

SEC("kretprobe/ret_sys_vfork")
int kretprobe__ret_sys_vfork(struct pt_regs *ctx)
{
    process_message_t sev = {0};
    exit_clone(ctx, &sev, PM_VFORK);
    return 0;
}

SEC("kprobe/sys_unshare_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_unshare_4_8, int flags)
{
    enter_unshare(ctx, flags);

    return 0;
}

SEC("kretprobe/ret_sys_unshare")
int kretprobe__ret_sys_unshare(struct pt_regs *ctx)
{
    process_message_t pm = {0};
    exit_unshare(ctx, &pm);
    return 0;
}

static __always_inline void push_exit(struct pt_regs *ctx, pprocess_message_t pm,
                                      process_message_type_t pm_type, u32 pid)
{
    void *ts = (void *)bpf_get_current_task();
    int ret = fill_syscall(&pm->u.syscall_info, ts, pid);
    if (ret > 0) return;
    if (ret < 0) {
        push_warning(ctx, pm, pm_type);
        return;
    }

    pm->type = pm_type;
    push_message(ctx, pm);
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
