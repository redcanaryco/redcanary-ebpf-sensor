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

typedef struct {
    process_message_type_t type;
    union {
        int unshare_flags;
        clone_info_t clone_info;
    };
} incomplete_event_t;

struct bpf_map_def SEC("maps/incomplete_events") incomplete_events = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_event_t),
    .max_entries = 1024,
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
// CPU. The message is purposefully not cleared so its data (in
// particular ev->event_id, and ev->type) can be reused if
// necessary.
static __always_inline int push_message(struct pt_regs *ctx, pprocess_message_t ev)
{
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
}

// sends PM_ENTER_DONE to signal the end of an enter_* event (i.e, a
// kprobe). Re-uses ev->event_id but sets the other fields.
static __always_inline void push_enter_done(struct pt_regs *ctx, pprocess_message_t ev)
{
    ev->type = PM_ENTER_DONE;

    // not used for anything but it feels weird not to reset the union
    // holding the event data so we putting a dummy value.
    ev->u.r.retcode = 0;
    push_message(ctx, ev);
}

// Pushes the syscall event, setting up ev with a new event id
// (ev->event_id) to be used for any future events related to the same
// syscall. If an event was not sent -1 is returned, 0 otherwise. This
// *DOES NOT* save the event id in the process_ids map. See
// `start_syscall`
static __always_inline int push_syscall(struct pt_regs *ctx, pprocess_message_t ev,
                                                       syscall_pattern_type_t sp, void *ts, u64 pid_tgid)
{
    if (!offset_loaded()) return -1;
    if (!is_user_process(ts)) return -1;

    void *ptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_REAL_PARENT, &ptr, sizeof(ptr));

    u32 ppid = -1;
    read_value(ptr, CRC_TASK_STRUCT_TGID, &ppid, sizeof(ppid));

    u32 luid = -1;
    read_value(ts, CRC_TASK_STRUCT_LOGINUID, &luid, sizeof(luid));

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 random_num = bpf_get_prandom_u32();
    u32 tid = pid_tgid & 0xFFFFFFFF;

    ev->event_id = (u64)tid << 32 | random_num;

    ev->type = PM_SYSCALL_INFO;
    ev->u.syscall_info.pid = pid_tgid >> 32;
    ev->u.syscall_info.tid = tid;
    ev->u.syscall_info.ppid = ppid;
    ev->u.syscall_info.luid = luid;
    ev->u.syscall_info.euid = uid_gid >> 32;
    ev->u.syscall_info.egid = uid_gid & 0xFFFFFFFF;
    ev->u.syscall_info.mono_ns = bpf_ktime_get_ns();
    ev->u.syscall_info.syscall_pattern = sp;

    push_message(ctx, ev);

    return 0;
}

static __always_inline int fill_syscall(syscall_info_t* syscall_info, void *ts, u64 pid_tgid) {
    if (!offset_loaded()) return -1;
    if (!is_user_process(ts)) return -1;

    void *ptr = NULL;
    read_value(ts, CRC_TASK_STRUCT_REAL_PARENT, &ptr, sizeof(ptr));

    u32 ppid = -1;
    read_value(ptr, CRC_TASK_STRUCT_TGID, &ppid, sizeof(ppid));

    u32 luid = -1;
    read_value(ts, CRC_TASK_STRUCT_LOGINUID, &luid, sizeof(luid));

    u64 uid_gid = bpf_get_current_uid_gid();

    syscall_info->pid = pid_tgid >> 32;
    syscall_info->tid = pid_tgid & 0xFFFFFFFF;
    syscall_info->ppid = ppid;
    syscall_info->luid = luid;
    syscall_info->euid = uid_gid >> 32;
    syscall_info->egid = uid_gid & 0xFFFFFFFF;
    syscall_info->mono_ns = bpf_ktime_get_ns();
    syscall_info->pid = pid_tgid >> 32;

    return 0;
}

// A wrapper around push_syscall that additionally inserts a new entry
// into the process_ids map with the pid_tgid as the key and the event
// id as the value. This is useful if you need to retrieve the
// event_id in a separate program (such as the kretprobe counterpart
// to a kprobe).
static __always_inline int start_syscall(struct pt_regs *ctx, pprocess_message_t ev,
                                        syscall_pattern_type_t sp, void *ts, u64 pid_tgid)
{
    if (push_syscall(ctx, ev, sp, ts, pid_tgid) < 0) return -1;

    bpf_map_update_elem(&process_ids, &pid_tgid, &ev->event_id, BPF_ANY);

    return 0;
}

// Sends a discard event and returns true if the retcode in the ctx is
// an error code.
static __always_inline bool check_discard(struct pt_regs *ctx, pprocess_message_t ev)
{
    // check for < 0 rather than just non-zero because forks return a
    // positive value on successes (the pid of the new process)
    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) {
        ev->type = PM_DISCARD;
        ev->u.r.retcode = retcode;
        push_message(ctx, ev);

        return true;
    }

    return false;
}

static __always_inline void* get_current_exe()
{
    void *ts = (void *)bpf_get_current_task();
    if (!ts) return NULL;

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

static __always_inline void push_exit_exec(struct pt_regs *ctx, pprocess_message_t ev,
                                           void *exe)
{
    // TODO: It would be more efficient to combine these into a single
    // message

    ev->type = PM_FILE_INFO;
    ev->u.file_info = extract_file_info(exe);
    push_message(ctx, ev);

    ev->type = PM_RETCODE;
    ev->u.r.retcode = (u32)PT_REGS_RC(ctx);
    push_message(ctx, ev);
}

static __always_inline int push_string(struct pt_regs *ctx, pprocess_message_t ev,
                                       const char *ptr)
{
    #pragma unroll
    for (int j = 0; j < 5; j++) {
        int count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)ptr);
        if (count < 0) return -1;

        // no more truncating; argument is done
        if (count < VALUE_SIZE) {
            ev->u.v.truncated = FALSE;
            push_message(ctx, ev);

            return 0;
        }

        // mark it as truncated; get next chunk of same arg
        ev->u.v.truncated = TRUE;
        ptr+=VALUE_SIZE;
        push_message(ctx, ev);
    }

    // if we get here it means that the string was larger than 5 *
    // VALUE_SIZE but we did our best
    return 1;
}

static __always_inline void push_path(struct pt_regs *ctx, pprocess_message_t ev,
                                      void *ptr, tail_call_slot_t slot) {
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
    if (to_skip_p) {
        to_skip = *to_skip_p;
    }

    // go up to 125 directories up
    u32 skipped = 0;
    if (to_skip != 0) {
        // this number is large enough that we have to be explicit
        // when telling clang
        #pragma unroll 125
        for (int i = 0; i < 125; i++) {
            // Skip to the parent directory
            bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);
            if (!ptr) break;

            skipped += 1;
            if (skipped >= to_skip) break;
        }
    }

    char truncated = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (truncated == 0) {
            if (bpf_probe_read(&offset, sizeof(offset), ptr + name) < 0) goto Skip;
            if (!offset) goto Skip;
        }

        int count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, offset);
        if (count < 0) goto Skip;

        if (count == VALUE_SIZE) {
            truncated = 1;
            ev->u.v.truncated = TRUE;
            offset = offset + VALUE_SIZE;
            push_message(ctx, ev);
        } else {
            ev->u.v.truncated = FALSE;
            push_message(ctx, ev);

            // get the parent
            void *old_ptr = ptr;
            bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);

            // there is no parent or parent points to itself
            if (!ptr || old_ptr == ptr) goto Skip;

            to_skip += 1;
            truncated = 0;
        }
    }

    // update to_skip, reuse skipped as index by resetting it
    skipped = 0;
    bpf_map_update_elem(&read_path_skip, &skipped, &to_skip, BPF_ANY);

    // tail call back in
    bpf_tail_call(ctx, &tail_call_table, slot);

Skip:
    skipped = 0;
    bpf_map_delete_elem(&read_path_skip, &skipped);
}

static __always_inline int process_argv(struct pt_regs *ctx, pprocess_message_t ev,
                                        const char __user *const __user *argv, u32 tail_index) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *idp = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (idp == NULL) return -1;

    ev->event_id = *idp;
    ev->type = PM_COMMAND_LINE;

    u32 always_zero = 0;
    u32 arg_num = 0;

    // check if we have tailed-back before; if so set arg_num
    u32 *parg_num = bpf_map_lookup_elem(&read_flush_index, &always_zero);
    if (parg_num != NULL) {
        arg_num = *parg_num;
    }

    // this number was arrived at experimentally, increasing it will result in too many
    // instructions for older kernels
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        char *ptr = NULL;
        int ret = bpf_probe_read(&ptr, sizeof(ptr), (void *)argv + (arg_num * sizeof(argv)));
        if (ret < 0 || ptr == NULL) goto Next;

        // we are ignoring the case of the string having been too
        // large. If this becomes a problem in practice we can tweak
        // the values somewhat.
        if (push_string(ctx, ev, ptr) < 0) goto Next;

        arg_num++;
    }

    // we have to tail back because we may not be done
    bpf_map_update_elem(&read_flush_index, &always_zero, &arg_num, BPF_ANY);
    bpf_tail_call(ctx, &tail_call_table, tail_index);

Next:;
    bpf_map_update_elem(&read_flush_index, &always_zero, &always_zero, BPF_ANY);

    return 0;
}

static __always_inline int enter_exec_4_11(struct pt_regs *ctx, pprocess_message_t ev,
                                           syscall_pattern_type_t sp)
{
    // if the ID already exists, we are tail-calling into ourselves, skip ahead to reading the path
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *id_p = bpf_map_lookup_elem(&process_ids, &pid_tgid);

    void *ts = (void *)bpf_get_current_task();
    if (!ts) return -1;

    if (id_p) {
        ev->event_id = *id_p;
        goto Pwd;
    }

    if (start_syscall(ctx, ev, sp, ts, pid_tgid) < 0) return -1;
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid & 0xFFFFFFFF;
    // deliberately not using BPF_ANY because we do not want to
    // overwrite it if another thread has already called for exec
    if (bpf_map_update_elem(&exec_tids, &pid, &tid, BPF_NOEXIST) < 0) {
        bpf_map_delete_elem(&process_ids, &pid_tgid);
        return -1;
    }

    u32 to_skip = 0;
    bpf_map_update_elem(&read_path_skip, &to_skip, &to_skip, BPF_ANY);

Pwd:;
    void *pwd_ptr = NULL;
    // task_struct->fs
    if (read_value(ts, CRC_TASK_STRUCT_FS, &pwd_ptr, sizeof(pwd_ptr)) < 0) return 0;

    // &(fs->pwd)
    pwd_ptr = offset_ptr(pwd_ptr, CRC_FS_STRUCT_PWD);
    if (pwd_ptr == NULL) return 0;

    ev->type = PM_PWD;
    push_path(ctx, ev, pwd_ptr, SYS_EXECVE_4_11);

    return 0;
}

SEC("kprobe/sys_execve_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_tc_argv,
                       const char __user *filename,
                       const char __user *const __user *argv)
{
    process_message_t sev = {0};

    if (process_argv(ctx, &sev, argv, SYS_EXECVE_TC_ARGV) < 0) return 0;

    // pushing arguments are the last thing our execve* kprobes do. If
    // this code is changed such that we tail call into another
    // program afterwards we need to change where we push the done
    // event.
    push_enter_done(ctx, &sev);

    return 0;
}

SEC("kprobe/sys_execveat_tc_argv")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_tc_argv,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv)
{
    process_message_t sev = {0};

    if (process_argv(ctx, &sev, argv, SYS_EXECVEAT_TC_ARGV) < 0) return 0;

    // pushing arguments are the last thing our execve* kprobes do. If
    // this code is changed such that we tail call into another
    // program afterwards we need to change where we push the done
    // event.
    push_enter_done(ctx, &sev);

    return 0;
}

SEC("kprobe/sys_execveat_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execveat_4_11,
                       int fd, const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp,
                       int flags)
{
    // create the event early so it can be re-used to save stack space
    process_message_t sev = {0};

    // OK to return early. No events are sent on a -1
    if (enter_exec_4_11(ctx, &sev, SP_EXECVEAT) < 0) return 0;

    // WARNING: sys_execveat_tc_argv relies on it sending the *last*
    // message originating from this kprobe. If you change this code
    // such that this tail call is somehow no longer the last action
    // (e.g., tail call to itself instead of separate program) you
    // need to change where we send the PM_ENTER_DONE event
    bpf_tail_call(ctx, &tail_call_table, SYS_EXECVEAT_TC_ARGV);

    return 0;
}

SEC("kprobe/sys_execve_4_11")
int BPF_KPROBE_SYSCALL(kprobe__sys_execve_4_11,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp)
{
    // create the event early so it can be re-used to save stack space
    process_message_t sev = {0};

    // OK to return early. No events are sent on a -1
    if (enter_exec_4_11(ctx, &sev, SP_EXECVE) < 0) return 0;

    // A filename should always be here but just in case do not return
    // early in its absence because we still want to tail call for
    // argv to trigger `PM_ENTER_DONE`
    if (filename) {
        sev.type = PM_EXEC_FILENAME;
        sev.u.v.value[0] = '\0';
        sev.u.v.truncated = FALSE;

        push_string(ctx, &sev, filename);
    }

    // WARNING: sys_execve_tc_argv relies on it sending the *last*
    // message originating from this kprobe. If you change this code
    // such that this tail call is somehow no longer the last action
    // (e.g., tail call to itself instead of separate program) you
    // need to change where we send the PM_ENTER_DONE event
    bpf_tail_call(ctx, &tail_call_table, SYS_EXECVE_TC_ARGV);

    return 0;
}

SEC("kretprobe/ret_sys_execve_4_8")
int kretprobe__ret_sys_execve_4_8(struct pt_regs *ctx)
{
    // the exec may have started in a different thread so find it
    // using exec_tids
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u32 *tid = bpf_map_lookup_elem(&exec_tids, &pid);
    if (!tid) goto Done;

     // use the tid that started the exec instead of our own tid
    pid_tgid = (u64)pid << 32 | *tid;
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (!id) goto Done;

    // re-use the same ev to save stack space
    process_message_t sev = {0};
    sev.event_id = *id;

    if (check_discard(ctx, &sev)) goto Done;

    void *ptr = get_current_exe();
    if (!ptr) goto Done;

    push_exit_exec(ctx, &sev, ptr);

Done:
    bpf_map_delete_elem(&exec_tids, &pid);
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    return 0;
}

SEC("kretprobe/ret_sys_execveat_4_8")
int kretprobe__ret_sys_execveat_4_8(struct pt_regs *ctx)
{
    // the exec may have started in a different thread so find it
    // using exec_tids
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 *tid = bpf_map_lookup_elem(&exec_tids, &pid);
    if (!tid) goto Done;

    // use the tid that started the exec instead of our own tid
    pid_tgid = (u64)pid << 32 | *tid;
    u64 *id = bpf_map_lookup_elem(&process_ids, &pid_tgid);
    if (!id) goto Done;

    // re-use the same ev to save stack space
    process_message_t sev = {0};
    sev.event_id = *id;

    if (check_discard(ctx, &sev)) goto Done;

    void *ptr = get_current_exe();
    if (!ptr) goto Done;

    sev.type = PM_EXEC_FILENAME_REV;
    void *path = offset_ptr(ptr, CRC_FILE_F_PATH);
    push_path(ctx, &sev, path, RET_SYS_EXECVEAT_4_8);

    push_exit_exec(ctx, &sev, ptr);

Done:
    bpf_map_delete_elem(&exec_tids, &pid);
    bpf_map_delete_elem(&process_ids, &pid_tgid);
    return 0;
}

static __always_inline int enter_clone(process_message_type_t pm, unsigned long flags)
{
    // we do not care about threads spawning; ignore clones that would
    // share the same thread group as the parent.
    if (flags & CLONE_THREAD) return -1;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_event_t event = {0};
    event.type = pm;
    event.clone_info.flags = flags;

    bpf_map_update_elem(&incomplete_events, &pid_tgid, &event, BPF_ANY);

    return 0;
}

// handles the kretprobe of clone-like syscalls (fork, vfork, clone, clone3)
static __always_inline int exit_clonex(struct pt_regs *ctx, pprocess_message_t ev, process_message_type_t pm)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_event_t *event = (incomplete_event_t *) bpf_map_lookup_elem(&incomplete_events, &pid_tgid);
    if (event == NULL) return -1;

    bpf_map_delete_elem(&incomplete_events, &pid_tgid);
    if (event->type != pm) return -1;

    int retcode = PT_REGS_RC(ctx);
    if (retcode < 0) return -1;

    void *ts = (void *)bpf_get_current_task();
    if (!ts) return -1;

    if (fill_syscall(&ev->u.syscall_info, ts, pid_tgid) < 0) return -1;

    ev->type = pm;
    ev->u.syscall_info.data.clone_info = event->clone_info;
    ev->u.syscall_info.retcode = retcode;

    return push_message(ctx, ev);
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
    enter_clone(PM_CLONE, flags);

    return 0;
}

SEC("kprobe/sys_clone3")
int BPF_KPROBE_SYSCALL(kprobe__sys_clone3, struct clone_args __user *uargs, size_t size)
{
    u64 flags = 0;
    bpf_probe_read(&flags, sizeof(u64), &uargs->flags);

    enter_clone(PM_CLONE3, flags);

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
        // only deleting for the error case
        bpf_map_delete_elem(&incomplete_events, &pid_tgid);
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
    if (npid != ntgid) return 0;

    // deliberately not deleting from the map - we'll let the
    // kretprobe do that and send the event
    event->clone_info.child_pid = ntgid;

    return 0;
}

SEC("kprobe/sys_fork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_fork_4_8)
{
    enter_clone(PM_FORK, 0);

    return 0;
}

SEC("kprobe/sys_vfork_4_8")
int BPF_KPROBE_SYSCALL(kprobe__sys_vfork_4_8)
{
    enter_clone(PM_VFORK, 0);

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

    bpf_map_update_elem(&incomplete_events, &pid_tgid, &event, BPF_ANY);

    return 0;
}

SEC("kretprobe/ret_sys_unshare")
int kretprobe__ret_sys_unshare(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_event_t *event = (incomplete_event_t *) bpf_map_lookup_elem(&incomplete_events, &pid_tgid);
    if (event == NULL) return 0;

    bpf_map_delete_elem(&incomplete_events, &pid_tgid);
    if (event->type != PM_UNSHARE) return 0;

    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) return 0;

    void *ts = (void *)bpf_get_current_task();
    if (!ts) return 0;

    process_message_t sev = {0};
    if (fill_syscall(&sev.u.syscall_info, ts, pid_tgid) < 0) return 0;

    sev.type = PM_UNSHARE;
    sev.u.syscall_info.data.unshare_flags = event->unshare_flags;
    sev.u.syscall_info.retcode = retcode;

    return push_message(ctx, &sev);
}

static __always_inline int push_exit(struct pt_regs *ctx, pprocess_message_t ev,
                                      process_message_type_t pm, u64 pid_tgid) {
    void *ts = (void *)bpf_get_current_task();
    if (!ts) return -1;

    if (fill_syscall(&ev->u.syscall_info, ts, pid_tgid) < 0) return -1;
    ev->type = pm;

    return push_message(ctx, ev);
}

SEC("kprobe/sys_exit")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit, int status)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // exit of a non-main thread
    if ((pid_tgid >> 32) ^ (pid_tgid & 0xFFFFFFFF)) return 0;

    process_message_t sev = {0};
    push_exit(ctx, &sev, PM_EXIT, pid_tgid);

    return 0;
}

SEC("kprobe/sys_exit_group")
int BPF_KPROBE_SYSCALL(kprobe__sys_exit_group, int status)
{
    process_message_t sev = {0};
    push_exit(ctx, &sev, PM_EXITGROUP, bpf_get_current_pid_tgid());

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
