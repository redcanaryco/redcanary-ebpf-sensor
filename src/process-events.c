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

typedef struct
{
    // the dentry to the path currently being processed. At the
    // beginning this is set to the top dentry of a path but it may be
    // set to the mount after the path to the file is done processing
    void *path;
    // the dentry to the mountpoint that will be processed for the
    // path. This is set to NULL once the path is processed and the
    // mount is being processed
    void *mountpoint;
} dentry_pair;

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
    .value_size = sizeof(dentry_pair),
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

typedef struct
{
    process_message_warning_t code;
    error_info_t info;
} local_warning_t;

// A "cpu local" warning so we can easily get/set the current warning
// at any point
struct bpf_map_def SEC("maps/warning") percpu_warning = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(local_warning_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

static __always_inline int set_local_warning(process_message_warning_t code, error_info_t info)
{
    local_warning_t warning = {0};
    warning.code = code;
    warning.info = info;
    u32 key = 0;
    return bpf_map_update_elem(&percpu_warning, &key, &warning, BPF_ANY);
}

/// Returns the offset to a field. If not found the current CPU's
/// warning_info is set and NULL is returned
static __always_inline u32* get_offset(u64 field) {
    u32 *offset = (u32 *)bpf_map_lookup_elem(&offsets, &field);
    if (offset == NULL) {
        error_info_t info = {0};
        info.offset_crc = field;
        set_local_warning(PMW_READING_FIELD, info);
    }

    return offset;
}

/// Equivalent to &(base->field). If not found the current CPU's
/// warning_info is set and NULL is returned
static __always_inline void* ptr_to_field(void *base, u64 field) {
    u32 *offset = get_offset(field);
    if (offset == NULL) return NULL;

    return base + *offset;
}

/// Equivalent to *dst = base->field. Returns 0 on success, or
/// negative and sets the current CPU's warning_info in case of
/// failure.
static __always_inline int read_field(void *base, u64 field, void *dst, size_t size) {
    void *ptr_to_ptr = ptr_to_field(base, field);
    if (ptr_to_ptr == NULL) return -1;

    int ret = bpf_probe_read(dst, size, ptr_to_ptr);
    if (ret < 0) {
        error_info_t info = {0};
        info.offset_crc = field;
        set_local_warning(PMW_PTR_FIELD_READ, info);
    }

    return ret;
}

/// Equivalent to void base->field. If not found or the pointer is
/// NULL the current CPU's warning_info is set and NULL is returned
static __always_inline void* read_field_ptr(void *base, u64 field) {
    void *dst = NULL;
    if (read_field(base, field, &dst, sizeof(dst)) < 0) return NULL;

    if (dst == NULL) {
        error_info_t info = {0};
        info.offset_crc = field;
        set_local_warning(PMW_NULL_FIELD, info);
    }

    return dst;
}

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

// accepts a pointer to a `task_struct`. Returns 0 if it is not
// user_process; 1 if it is, and -1 if an error occured.
static __always_inline int is_user_process(void *ts)
{
    void *mmptr = NULL;
    if (read_field(ts, CRC_TASK_STRUCT_MM, &mmptr, sizeof(mmptr)) < 0) {
        return -1;
    }
    return mmptr != NULL;
}

// pushes a message to the process_events perfmap for the current CPU.
static __always_inline int push_message(struct pt_regs *ctx, pprocess_message_t ev)
{
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
}

// pushes a warning to the process_events perfmap for the current CPU.
static __always_inline int push_warning(struct pt_regs *ctx, pprocess_message_t pm,
                                        process_message_type_t pm_type)
{
    pm->type = PM_WARNING;

    u32 key = 0;
    local_warning_t *warning = (local_warning_t *)bpf_map_lookup_elem(&percpu_warning, &key);
    if (warning != NULL) {
        pm->u.warning_info.code = warning->code;
        pm->u.warning_info.info = warning->info;
        // reset it so we don't accidentally re-use the same code/info in a new warning
        *warning = (local_warning_t){0};
    }

    pm->u.warning_info.pid_tgid = bpf_get_current_pid_tgid();
    pm->u.warning_info.message_type = pm_type;

    return push_message(ctx, pm);
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
    int ret = is_user_process(ts);
    if (ret < 1) return ret;

    void *real_parent = read_field_ptr(ts, CRC_TASK_STRUCT_REAL_PARENT);
    if (real_parent == NULL) return -1;

    u32 ppid = -1;
    if (read_field(real_parent, CRC_TASK_STRUCT_TGID, &ppid, sizeof(ppid)) < 0) return -1;

    u32 luid = -1;
    if (read_field(ts, CRC_TASK_STRUCT_LOGINUID, &luid, sizeof(luid)) < 0) return -1;

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
static __always_inline int write_path(struct pt_regs *ctx, dentry_pair *dentries, buf_t *buffer,
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
    u32 parent = *(u32 *)offset; // offset of d_parent

    int ret = 0;
// Anything we add to this for-loop will be repeated
// MAX_PATH_SEGMENTS_NOTAIL so be very careful of going over the max
// instruction limit (4096).
#pragma unroll MAX_PATH_SEGMENTS_NOTAIL
    for (int i = 0; i < MAX_PATH_SEGMENTS_NOTAIL; i++)
    {
        if (bpf_probe_read(&offset, sizeof(offset), dentries->path + name) < 0)
            return 0;

        // NAME_MAX doesn't include null character; so +1 to take it
        // into account. Not all systems enforce NAME_MAX so
        // truncation may happen per path segment. TODO: emit
        // truncation metrics to see if we need to care about this.
        ret = write_string((char *)offset, buffer, NAME_MAX + 1);
        if (ret < 0) goto WriteError;

        // get the parent
        void *old_dentry = dentries->path;
        bpf_probe_read(&dentries->path, sizeof(dentries->path), dentries->path + parent);

        // there is no parent or parent points to itself
        if ((dentries->path) == NULL || old_dentry == dentries->path)
            return 0;
    }

    bpf_tail_call(ctx, &tail_call_table, tail_call);

    error_info_t info = {0};
    info.tailcall = tail_call;
    set_local_warning(PMW_TAIL_CALL_MAX, info);

    return -1;

 WriteError:;
    error_info_t empty_info = {0};
    if (ret == -PMW_UNEXPECTED) {
        set_local_warning(PMW_READ_PATH_STRING, empty_info);
    } else {
        set_local_warning(-ret, empty_info);
    }

    return -1;
}

static __always_inline void exit_exec(struct pt_regs *ctx, process_message_type_t pm_type,
                                      tail_call_slot_t tail_call)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    dentry_pair *dentries = (dentry_pair *)bpf_map_lookup_elem(&percpu_dentries, &key);
    if (dentries == NULL) return;

    process_message_t *pm = (process_message_t *)buffer;
    int ret = 0;

    // We have been tail-called to find the exename, so go straight to
    // ExeName
    if (dentries->path != NULL) goto ExeName;

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
    pm->u.syscall_info.data.exec_info.argv_truncated = (u8) (argv_length > MAX_ARGV_LENGTH);
    argv_length = (argv_length) & (MAX_ARGV_LENGTH);

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

    // TODO: grab the mount that wraps path->mnt to find the real mount point
    dentries->path = read_field_ptr(path, CRC_PATH_DENTRY);
    if (dentries->path == NULL) goto EmitWarning;

 ExeName:;
    /* WRITE EXE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, dentries, buffer, tail_call);

    // reset skips back to 0. This will automatically update it in the
    // map so no need to do a bpf_map_update_elem.
    dentries->path = NULL;
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
    push_warning(ctx, pm, pm_type);
}

SEC("kprobe/sys_exec_pwd")
int kprobe__sys_exec_pwd(struct pt_regs *ctx)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */

    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return 0;

    dentry_pair *dentries = (dentry_pair *)bpf_map_lookup_elem(&percpu_dentries, &key);
    if (dentries == NULL) return 0;

    int ret = 0;
    process_message_t *pm = (process_message_t *)buffer;
    process_message_type_t pm_type = pm->type;

    if (dentries->path != NULL) goto Pwd;

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

    // TODO: grab the mount that wraps pwd->mnt to find the real mount point
    // task_struct->fs->pwd.dentry
    dentries->path = read_field_ptr(path, CRC_PATH_DENTRY);
    if (dentries->path == NULL) goto Done;

 Pwd:;
    /* WRITE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, dentries, buffer, SYS_EXEC_PWD);

 Done:;
    /* PUSH THE EVENT AND RESET */
    dentries->path = NULL;

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
    int ret = fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32);
    if (ret > 0) return;
    if (ret < 0) goto EmitWarning;

    pm->type = pm_type;
    pm->u.syscall_info.data.clone_info = event.clone_info;
    pm->u.syscall_info.retcode = retcode;

    push_message(ctx, pm);

    goto Done;

 EventMismatch:;
    error_info_t info = {0};
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(PMW_PID_TGID_MISMATCH, info);

 EmitWarning:;
    push_warning(ctx, pm, pm_type);

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
    if (read_field(ts, CRC_TASK_STRUCT_PID, &npid, sizeof(npid)) < 0) {
        // don't bother emitting a warning; worst case we can use the retcode
        return 0;
    }

    u32 ntgid = 0;
    if (read_field(ts, CRC_TASK_STRUCT_TGID, &ntgid, sizeof(ntgid)) < 0) {
        // don't bother emitting a warning; worst case we can use the retcode
        return 0;
    }

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

    int ret = fill_syscall(&pm.u.syscall_info, ts, pid_tgid >> 32);
    if (ret > 0) return 0;
    if (ret < 0) goto EmitWarning;

    pm.type = PM_UNSHARE;
    pm.u.syscall_info.data.unshare_flags = event.unshare_flags;
    pm.u.syscall_info.retcode = retcode;

    push_message(ctx, &pm);
    goto Done;

 EventMismatch:;
    error_info_t info = {0};
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(PMW_PID_TGID_MISMATCH, info);

 EmitWarning:;
    push_warning(ctx, &pm, PM_UNSHARE);

 Done:;
    // only delete at the very end so the event pointer above is valid
    // for the duration of this function.
    bpf_map_delete_elem(&incomplete_unshares, &pid_tgid);
    return 0;

 NoEvent:;
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
