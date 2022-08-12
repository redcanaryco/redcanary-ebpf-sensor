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

// maximum number of arguments we can read of an argv before doing a
// tail call. It may be lowered if we go over the number of
// instructions allowed.
#define MAX_ARGS_NOTAIL 75

// used to send data gathered/calculated in a kprobe to the kretprobe.
typedef struct {
    process_message_type_t type;
    union {
        int unshare_flags;
        clone_info_t clone_info;
        u64 exec_id;
    };
} incomplete_event_t;

// used for events with flexible sizes (i.e., exec*) so it can send
// extra data. Used in conjuction with a map such that it does not use
// the stack size limit.
typedef struct {
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

// A per cpu counter so we can hold it across tail calls.
struct bpf_map_def SEC("maps/percpu_counter") percpu_counter = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
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

// A map of events that have started (a kprobe) but are yet to finish
// (the kretprobe).
struct bpf_map_def SEC("maps/incomplete_events") incomplete_events = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_event_t),
    .max_entries = 8 * 1024,
    .pinning = 0,
    .namespace = "",
};

// A map of what pids have started an exec; with the value pointing to
// what thread started it.
struct bpf_map_def SEC("maps/exec_tids") exec_tids = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),   // pid
    .value_size = sizeof(u32), //tid
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
static __always_inline void write_null_char(buf_t *buffer, u32 *offset) {
    // bpf_probe_read_str always write a null character at the end,
    // even when truncating. So this is either adding a null at the
    // end or replacing a null with another null when full which is OK.
    buffer->buf[*offset & (MAX_PERCPU_BUFFER - 1)] = '\0';
    *offset = *offset + 1;
}

// returns NULL if offsets have not yet been loaded
static __always_inline void* offset_loaded()
{
    u64 offset = CRC_LOADED;
    return bpf_map_lookup_elem(&offsets, &offset);
}

// accepts a pointer a `task_struct`. Returns NULL if the task_struct
// belongs to a kernel process
static __always_inline void* is_user_process(void *ts)
{
    void *mmptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_MM, &mmptr, sizeof(mmptr));
    return mmptr;
}

// pushes a message to the process_events perfmap for the current
// CPU.
static __always_inline int push_message(struct pt_regs *ctx, pprocess_message_t ev) {
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
}

// pushes a message with an extra `dynamic_size` number of bytes. It
// caps the message to `MAX_PERCPU_BUFFER - 1` to appease verifier
// however. The "-1" is there to make it an easy bit cap against a
// power of two; it may drop an null byte out of the string which is
// OK.
static __always_inline int push_flexible_message(struct pt_regs *ctx, pprocess_message_t ev, u64 dynamic_size) {
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, dynamic_size & (MAX_PERCPU_BUFFER - 1));
}

// writes the string into the provided buffer w/ offset. On a
// succesful write it modifies the offset with the length of the read
// string. It deliberately does not handle truncations; it just reads
// up to `max_string`.
static __always_inline int write_string(const char *string, buf_t *buffer, u32 *offset, const u32 max_string) {
    // A smarter implementation of this wouldn't use max_string but
    // instead would just check MAX_PERCPU_BUFFER - *offset as the max
    // that it can write. However, the verifier seems allergic to an
    // smarter implementation as it complains about potential out of
    // bounds or negative values. While perhaps theoretically possible
    // to improve this with just the right incantations (and maybe
    // turning off some compiler optimizaitons that remove some
    // checks) at this time this is considered good enough (TM).

    // already too full
    if (*offset > MAX_PERCPU_BUFFER - max_string) return -PMW_BUFFER_FULL;

    int sz = bpf_probe_read_str(&buffer->buf[*offset], max_string, string);
    if (sz < 0) {
        return -PMW_UNEXPECTED;
    } else {
        *offset = *offset + sz;
        return sz;
    }
}

// fills the syscall_info with all the common values. Returns 1 if the
// task struct is not a user process or if the offsets have not yet
// been loaded.
static __always_inline int fill_syscall(syscall_info_t* syscall_info, void *ts, u32 pid) {
    if (!offset_loaded()) return 1;
    if (!is_user_process(ts)) return 1;

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

// returns the running executable on the task struct
static __always_inline void* get_current_exe(void *ts) {
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

    file_info_t file_info = {
        .inode = i_ino,
        .devmajor = MAJOR(i_dev),
        .devminor = MINOR(i_dev),
    };

    bpf_get_current_comm(&file_info.comm, sizeof(file_info.comm));

    return file_info;
}

// writes a d_path into a buffer - tail calling if necessary
static __always_inline int write_path(struct pt_regs *ctx, void *ptr, buf_t *buffer,
                                      u32 *skips, u32 *buffer_offset, tail_call_slot_t tail_call) {
    // any early exit at the start is unexpected
    int ret = -PMW_UNEXPECTED;
    if (read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr)) < 0) goto Skip;

    void *offset = NULL;
    u64 offset_key = 0;

    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 name = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    SET_OFFSET(CRC_QSTR_NAME);
    name = name + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset; // offset of d_parent

    // we cannot skip anymore - just call it done
    if (*skips > MAX_PATH_SEGMENTS_SKIP) {
        ret = -PMW_MAX_PATH;
        goto Skip;
    }

    // at this point let's assume success
    ret = 0;

    // skip segments we read before the current tail_call
    // Anything we add to this for-loop will be repeated
    // MAX_PATH_SEGMENTS_SKIP so be very careful of going over the max
    // instruction limit (4096).
    #pragma unroll MAX_PATH_SEGMENTS_SKIP
    for (int i = 0; i < MAX_PATH_SEGMENTS_SKIP; i++) {
        if (i == *skips) break;
        // Skip to the parent directory
        if (bpf_probe_read(&ptr, sizeof(ptr), ptr + parent) < 0) goto Skip;
    }

    // Anything we add to this for-loop will be repeated
    // MAX_PATH_SEGMENTS_NOTAIL so be very careful of going over the max
    // instruction limit (4096).
    #pragma unroll MAX_PATH_SEGMENTS_NOTAIL
    for (int i = 0; i < MAX_PATH_SEGMENTS_NOTAIL; i++) {
        if (bpf_probe_read(&offset, sizeof(offset), ptr + name) < 0) goto Skip;
        // NAME_MAX doesn't include null character; so +1 to take it
        // into account. Mot all systems enforce NAME_MAX so
        // truncation may happen per path segment. TODO: emit
        // truncation metrics to see if we need to care about this.
        int sz = write_string((char *) offset, buffer, buffer_offset, NAME_MAX + 1);
        if (sz < 0) {
            ret = sz;
            goto Skip;
        }

        // get the parent
        void *old_ptr = ptr;
        bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);

        // there is no parent or parent points to itself
        if (!ptr || old_ptr == ptr) goto Skip;
    }

    // skip the already written path segments
    *skips = *skips + MAX_PATH_SEGMENTS_NOTAIL;

    // we cannot skip anymore - just call it done
    if (*skips > MAX_PATH_SEGMENTS_SKIP) {
        ret = -PMW_MAX_PATH;
        goto Skip;
    }

    bpf_tail_call(ctx, &tail_call_table, tail_call);

    ret = -PMW_TAIL_CALL_MAX;

Skip:
    return ret;
}

// writes argv into the buffer - tail calling if necessary
static __always_inline int write_argv(struct pt_regs *ctx, const char __user *const __user *argv,
                                       buf_t *buffer, u32 *buffer_offset, tail_call_slot_t tc_slot) {
    u32 key = 0;
    u32 *arg_num = (u32 *) bpf_map_lookup_elem(&percpu_counter, &key);
    if (arg_num == NULL) return 0;

    int ret = 0;

    // this number was arrived at experimentally, increasing it will result in too many
    // instructions for older kernels
    #pragma unroll MAX_ARGS_NOTAIL
    for (int i = 0; i < MAX_ARGS_NOTAIL; i++) {
        char *ptr = NULL;
        int ret = bpf_probe_read(&ptr, sizeof(ptr), (void *) &argv[*arg_num]);
        if (ret < 0 || ptr == NULL) goto Done;

        // we are ignoring the case of the string having been too
        // large. If this becomes a problem in practice we can tweak
        // the values somewhat.
        int sz = write_string(ptr, buffer, buffer_offset, 1024);
        if (sz < 0) {
            ret = sz;
            goto Done;
        }

        *arg_num = *arg_num + 1;
    }

    bpf_tail_call(ctx, &tail_call_table, tc_slot);

    ret = -PMW_TAIL_CALL_MAX;

 Done:;
    *arg_num = 0;
    return ret;
}

SEC("kprobe/sys_execve_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_tc_argv,
                       const char __user *filename,
                       const char __user *const __user *argv) {
    u32 key = 0;
    buf_t *buffer = (buf_t *) bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return 0;

    process_message_t *pm = (process_message_t *) buffer;

    int ret = write_argv(ctx, argv, buffer, &pm->u.string_info.buffer_length, SYS_EXECVE_TC_ARGV);
    if (ret < 0) {
        pm->type = PM_WARNING;
        pm->u.warning_info.message_type = PM_EXECVE;
        pm->u.warning_info.code = -ret;

        push_message(ctx, pm);

        // deliberately not returning early so we can still push the
        // message for the bit we have
    }

    write_null_char(buffer, &pm->u.string_info.buffer_length);

    if (push_flexible_message(ctx, pm, pm->u.string_info.buffer_length) < 0) {
        // if this message failed to be sent let's remove the events
        // from the maps so the kretprobe doesn't do useless work
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        bpf_map_delete_elem(&exec_tids, &pid);
        bpf_map_delete_elem(&incomplete_events, &pid_tgid);
    }

    return 0;
}

static __always_inline int write_pwd(struct pt_regs *ctx, buf_t *buffer, u32 *offset,
                                     u32 *skips, tail_call_slot_t tc_slot) {
    void *ts = (void *)bpf_get_current_task();
    int ret = -PMW_UNEXPECTED;

    void *pwd_ptr = NULL;
    // task_struct->fs
    if (read_value(ts, CRC_TASK_STRUCT_FS, &pwd_ptr, sizeof(pwd_ptr)) < 0) goto Done;

    // &(fs->pwd)
    pwd_ptr = offset_ptr(pwd_ptr, CRC_FS_STRUCT_PWD);
    if (pwd_ptr == NULL) goto Done;

    ret = write_path(ctx, pwd_ptr, buffer, skips, offset, tc_slot);
    if (ret < 0) goto Done;

    ret = 0;

    // add an extra null byte to signify string section end
    write_null_char(buffer, offset);

 Done:;
    // reset skips back to 0. This will automatically update it in the
    // map so no need to do a bpf_map_update_elem.
    *skips = 0;
    return ret;
}

static __always_inline void enter_exec(struct pt_regs *ctx, const char __user *filename,
                                       process_message_type_t pm_type, tail_call_slot_t pwd_slot,
                                       tail_call_slot_t argv_slot) {
    u32 key = 0;
    buf_t *buffer = (buf_t *) bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    u32 *skips = (u32 *) bpf_map_lookup_elem(&percpu_counter, &key);
    if (skips == NULL) return;

    process_message_t *pm = (process_message_t *) buffer;

    int ret = -PMW_UNEXPECTED;
    error_info_t einfo = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (*skips != 0) {
        goto Pwd;
    }

    u32 tid = pid_tgid & 0xFFFFFFFF;

    // deliberately not using BPF_ANY because we do not want to
    // overwrite it if another thread has already called for exec
    ret = bpf_map_update_elem(&exec_tids, &pid, &tid, BPF_NOEXIST);
    if (ret < 0) {
        einfo.err = ret;
        ret = -PMW_DOUBLE_EXEC;
        goto Error;
    }

    incomplete_event_t event = {0};
    event.type = pm_type;
    event.exec_id = (u64)tid << 32 | bpf_get_prandom_u32();

    pm->type = PM_STRINGS;
    pm->u.string_info.event_id = event.exec_id;
    pm->u.string_info.buffer_length = sizeof(process_message_t);

    // should only happen if `incomplete_events` is filled
    ret = bpf_map_update_elem(&incomplete_events, &pid_tgid, &event, BPF_ANY);
    if (ret) {
        einfo.err = ret;
        ret = -PMW_FILLED_EVENTS;
        goto Error;
    }

    if (filename) {
        // PATH_MAX is (theoretically) the max path that can be given
        // to a syscall. Note that this is NOT the max absolute path,
        // but that is okay since we just care about what was passed
        // to the syscall.
        ret = write_string(filename, buffer, &pm->u.string_info.buffer_length, PATH_MAX);
        if (ret < 0) {
            goto Error;
        }

        // add an extra null byte to signify string section end
        write_null_char(buffer, &pm->u.string_info.buffer_length);
    }

Pwd:;
    ret = write_pwd(ctx, buffer, &pm->u.string_info.buffer_length, skips, pwd_slot);
    if (ret < 0) {
        goto Error;
    }

    // tail call to the argv handling program
    bpf_tail_call(ctx, &tail_call_table, argv_slot);

    // tail call shouldn't fail since we don't let pwd use up all the
    // tail calls but just in case it happens let's emit an error
    ret = -PMW_TAIL_CALL_MAX;

 Error:;
    pm->type = PM_WARNING;
    pm->u.warning_info.message_type = pm_type;
    pm->u.warning_info.code = -ret;
    pm->u.warning_info.info = einfo;
    push_message(ctx, pm);

    bpf_map_delete_elem(&exec_tids, &pid);
    bpf_map_delete_elem(&incomplete_events, &pid_tgid);
}

SEC("kprobe/sys_execveat_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_tc_argv,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv) {
    u32 key = 0;
    buf_t *buffer = (buf_t *) bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return 0;

    process_message_t *pm = (process_message_t *) buffer;

    int ret = write_argv(ctx, argv, buffer, &pm->u.string_info.buffer_length, SYS_EXECVEAT_TC_ARGV);
    if (ret < 0) {
        pm->type = PM_WARNING;
        pm->u.warning_info.message_type = PM_EXECVEAT;
        pm->u.warning_info.code = -ret;

        push_message(ctx, pm);

        // deliberately not returning early so we can still push the
        // message for the bit we have
    }

    write_null_char(buffer, &pm->u.string_info.buffer_length);

    if (push_flexible_message(ctx, pm, pm->u.string_info.buffer_length) < 0) {
        // if this message failed to be sent - let's remove the events
        // from the maps so the kretprobe doesn't do useless work
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;

        bpf_map_delete_elem(&exec_tids, &pid);
        bpf_map_delete_elem(&incomplete_events, &pid_tgid);
    }

    return 0;
}

SEC("kprobe/sys_execveat_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_4_11,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags) {
    enter_exec(ctx, NULL, PM_EXECVEAT, SYS_EXECVEAT_4_11, SYS_EXECVEAT_TC_ARGV);

    return 0;
}

SEC("kprobe/sys_execve_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_4_11,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp) {
    // probably not needed but in execveat we explicitly pass NULL to
    // differentiate so let's make 100% certain this isn't NULL as
    // that is an invalid exec argument anyway
    if (!filename) return 0;

    enter_exec(ctx, filename, PM_EXECVE, SYS_EXECVE_4_11, SYS_EXECVE_TC_ARGV);

    return 0;
}

static __always_inline int exit_exec(struct pt_regs *ctx, process_message_t *pm,
                                     void *ts, void *exe, process_message_type_t pm_type) {
    // the exec may have started in a different thread so find it
    // using exec_tids
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 *tid = bpf_map_lookup_elem(&exec_tids, &pid);

    // not going to Done because there is nothing to delete at this point.
    if (!tid) return 1;

    // use the tid that started the exec instead of our own tid
    pid_tgid = (u64)pid << 32 | *tid;

    int ret = 1;
    error_info_t einfo = {0};
    incomplete_event_t *event = (incomplete_event_t *) bpf_map_lookup_elem(&incomplete_events, &pid_tgid);
    if (event == NULL) {
        // unlike other events where we might miss incomplete events
        // due to the program starting halfway through a syscall;
        // finding an exec_tid but not an incomplete_event means that
        // something did not get deleted appropiately or that
        // something got deleted too early - either way let's inform
        // user space
        ret = -PMW_MISSING_EVENT;
        goto Done;
    }

    if (event->type != pm_type) {
        ret = -PMW_WRONG_TYPE;
        einfo.actual_type = event->type;
        goto Done;
    }

    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) {
        pm->type = PM_DISCARD;
        pm->u.discard_info.event_id = event->exec_id;
        push_message(ctx, pm);
        goto Done;
    }

    if (fill_syscall(&pm->u.syscall_info, ts, pid) != 0) {
        // don't exit early without discarding
        pm->type = PM_DISCARD;
        pm->u.discard_info.event_id = event->exec_id;
        push_message(ctx, pm);

        goto Done;
    }

    ret = 0;
    pm->type = pm_type;
    pm->u.syscall_info.data.exec_info.event_id = event->exec_id;
    pm->u.syscall_info.retcode = retcode;
    pm->u.syscall_info.data.exec_info.file_info = extract_file_info(exe);

 Done:;
    // only delete at the very end so the event and the tid pointers
    // above are valid for the duration of this function.
    bpf_map_delete_elem(&exec_tids, &pid);
    bpf_map_delete_elem(&incomplete_events, &pid_tgid);

    if (ret < 0) {
        pm->type = PM_WARNING;
        pm->u.warning_info.message_type = pm_type;
        pm->u.warning_info.code = -ret;
        pm->u.warning_info.info = einfo;

        push_message(ctx, pm);

        // do not return the ret so we do not accidentally send the
        // warning again
        return 1;
    }

    return ret;
}

SEC("kretprobe/ret_sys_execve_4_8")
int kretprobe__ret_sys_execve_4_8(struct pt_regs *ctx)
{
    process_message_t pm = {0};
    void *ts = (void *)bpf_get_current_task();
    void *exe = get_current_exe(ts);
    int ret = 0;
    if (!exe) {
        ret = -PMW_UNEXPECTED;
        goto Done;
    }

    ret = exit_exec(ctx, &pm, ts, exe, PM_EXECVE);
    if (ret != 0) goto Done;

    push_message(ctx, &pm);

 Done:;
    return 0;
}

SEC("kretprobe/ret_sys_execveat_4_8")
int kretprobe__ret_sys_execveat_4_8(struct pt_regs *ctx) {
    u32 key = 0;
    buf_t *buffer = (buf_t *) bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return 0;

    u32 *skips = (u32 *) bpf_map_lookup_elem(&percpu_counter, &key);
    if (skips == NULL) return 0;

    void *ts = (void *)bpf_get_current_task();
    void *exe = get_current_exe(ts);
    int ret = 0;
    if (!exe) {
        ret = -PMW_UNEXPECTED;
        goto Done;
    }

    process_message_t *pm = (process_message_t *) buffer;

    if (*skips != 0) {
        goto Pwd;
    }

    pm->u.syscall_info.data.exec_info.buffer_length = sizeof(process_message_t);
    ret = exit_exec(ctx, pm, ts, exe, PM_EXECVEAT);
    if (ret != 0) goto Done;

 Pwd:;
    void *path = offset_ptr(exe, CRC_FILE_F_PATH);
    ret = write_path(ctx, path, buffer, skips,
                     &pm->u.syscall_info.data.exec_info.buffer_length, RET_SYS_EXECVEAT_4_8);

    // reset skips back to 0. This will automatically update it in the
    // map so no need to do a bpf_map_update_elem.
    *skips = 0;

    if (ret < 0) goto Done;

    // add an extra null byte to signify string section end
    write_null_char(buffer, &pm->u.syscall_info.data.exec_info.buffer_length);

    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

 Done:;
    if (ret < 0) {
        pm->type = PM_WARNING;
        pm->u.warning_info.message_type = PM_EXECVEAT;
        pm->u.warning_info.code = -ret;

        push_message(ctx, pm);
    }

    return 0;
}

static __always_inline void enter_clone(struct pt_regs *ctx, process_message_type_t pm_type, unsigned long flags) {
    // we do not care about threads spawning; ignore clones that would
    // share the same thread group as the parent.
    if (flags & CLONE_THREAD) return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_event_t event = {0};
    event.type = pm_type;
    event.clone_info.flags = flags;

    int ret = bpf_map_update_elem(&incomplete_events, &pid_tgid, &event, BPF_ANY);
    if (ret < 0) {
        process_message_t pm = {0};
        pm.type = PM_WARNING;
        pm.u.warning_info.message_type = pm_type;
        pm.u.warning_info.code = PMW_FILLED_EVENTS;
        pm.u.warning_info.info = (error_info_t) { .err = ret };

        push_message(ctx, &pm);

        return;
    }

    return;
}

// handles the kretprobe of clone-like syscalls (fork, vfork, clone, clone3)
static __always_inline void exit_clonex(struct pt_regs *ctx, pprocess_message_t ev, process_message_type_t pm_type) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_event_t *event = (incomplete_event_t *) bpf_map_lookup_elem(&incomplete_events, &pid_tgid);
    if (event == NULL) return;

    if (event->type != pm_type) {
        process_message_t pm = {0};
        pm.type = PM_WARNING;
        pm.u.warning_info.message_type = pm_type;
        pm.u.warning_info.code = PMW_WRONG_TYPE;
        pm.u.warning_info.info = (error_info_t) { .actual_type = event->type };

        push_message(ctx, &pm);

        goto Done;
    }

    int retcode = PT_REGS_RC(ctx);
    if (retcode < 0) goto Done;

    void *ts = (void *)bpf_get_current_task();
    if (fill_syscall(&ev->u.syscall_info, ts, pid_tgid >> 32) != 0) goto Done;

    ev->type = pm_type;
    ev->u.syscall_info.data.clone_info = event->clone_info;
    ev->u.syscall_info.retcode = retcode;

    push_message(ctx, ev);

 Done:;
    // only delete at the every end so the event pointer above is
    // valid for the duration of this function.
    bpf_map_delete_elem(&incomplete_events, &pid_tgid);
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
    incomplete_event_t *event = (incomplete_event_t *) bpf_map_lookup_elem(&incomplete_events, &pid_tgid);
    if (event == NULL) return 0;

    if (event->type != PM_FORK &&
        event->type != PM_VFORK &&
        event->type != PM_CLONE &&
        event->type != PM_CLONE3) {
        // maybe a different syscall triggered this hook - we only
        // want to do the work in this kprobe for clone-like syscalls
        // so just exit early and do not change anything. If the event
        // type is actually wrong the kretprobe can handle the error
        // handling.

        return 0;
    }

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
    if (npid != ntgid) {
        // the kretprobe shouldn't care about it either
        bpf_map_delete_elem(&incomplete_events, &pid_tgid);
        return 0;
    }

    // deliberately not deleting from the map - we'll let the
    // kretprobe do that and send the event
    event->clone_info.child_pid = ntgid;

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
    incomplete_event_t event = {0};
    event.type = PM_UNSHARE;
    event.unshare_flags = flags;

    int ret = bpf_map_update_elem(&incomplete_events, &pid_tgid, &event, BPF_ANY);
    if (ret < 0) {
        process_message_t pm = {0};
        pm.type = PM_WARNING;
        pm.u.warning_info.message_type = PM_UNSHARE;
        pm.u.warning_info.code = PMW_FILLED_EVENTS;
        pm.u.warning_info.info = (error_info_t) { .err = ret };

        push_message(ctx, &pm);

        return 0;
    }

    return 0;
}

SEC("kretprobe/ret_sys_unshare")
int kretprobe__ret_sys_unshare(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_event_t *event = (incomplete_event_t *) bpf_map_lookup_elem(&incomplete_events, &pid_tgid);
    if (event == NULL) return 0;

    process_message_t pm = {0};

    if (event->type != PM_UNSHARE) {
        pm.type = PM_WARNING;
        pm.u.warning_info.message_type = PM_UNSHARE;
        pm.u.warning_info.code = PMW_WRONG_TYPE;
        pm.u.warning_info.info = (error_info_t) { .actual_type = event->type };
        push_message(ctx, &pm);

        goto Done;
    }

    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) goto Done;

    void *ts = (void *)bpf_get_current_task();

    if (fill_syscall(&pm.u.syscall_info, ts, pid_tgid >> 32) != 0) goto Done;

    pm.type = PM_UNSHARE;
    pm.u.syscall_info.data.unshare_flags = event->unshare_flags;
    pm.u.syscall_info.retcode = retcode;

    push_message(ctx, &pm);

 Done:;
    // only delete at the very end so the event pointer above is valid
    // for the duration of this function.
    bpf_map_delete_elem(&incomplete_events, &pid_tgid);
    return 0;
}

static __always_inline void push_exit(struct pt_regs *ctx, pprocess_message_t ev,
                                      process_message_type_t pm_type, u32 pid) {
    void *ts = (void *)bpf_get_current_task();
    if (fill_syscall(&ev->u.syscall_info, ts, pid) != 0) return;
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
    if ((pid) ^ (tid)) return 0;

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
