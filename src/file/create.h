#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/helpers.h"
#include "common/offsets.h"
#include "common/types.h"
#include "push_file_message.h"
#include "dentry.h"
#include "common/path.h"

typedef struct {
  u64 pid_tgid;
  u64 start_ktime_ns;
  void *target_vfsmount;  // vfsmount of the containing directory
  void *target_dentry;    // dentry of the new directory
  void *source;           // dentry for hard link, char for symlink
} incomplete_create_t;

// A map of mkdirs that have started (a kprobe) but are yet to finish
// (the kretprobe).
struct bpf_map_def SEC("maps/incomplete_creates") incomplete_creates = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(incomplete_create_t),
  .max_entries = 512,
  .pinning = 0,
  .namespace = "",
};

static __always_inline void enter_create(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_create_t event = {0};
    event.pid_tgid = pid_tgid;
    event.start_ktime_ns = bpf_ktime_get_ns();

    int ret = bpf_map_update_elem(&incomplete_creates, &pid_tgid, &event, BPF_ANY);
    if (ret < 0)
    {
        file_message_t fm = {0};
        fm.type = FM_WARNING;
        fm.u.warning.pid_tgid = pid_tgid;
        fm.u.warning.message_type.file = FM_CREATE;
        fm.u.warning.code = W_UPDATE_MAP_ERROR;
        fm.u.warning.info.err = ret;

        push_file_message(ctx, &fm);
    }
}

// The source parameter should be NULL if there is no source, a dentry for hard links, or a char * for symlink
static __always_inline void store_dentry(struct pt_regs *ctx, void *path, void *dentry, void *source)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    file_message_t fm = {0};

    load_event(incomplete_creates, pid_tgid, incomplete_create_t);
    if (event.target_dentry != NULL) goto NoEvent;

    event.target_dentry = dentry;
    event.target_vfsmount = read_field_ptr(path, CRC_PATH_MNT);
    if (event.target_vfsmount == NULL) goto EmitWarning;
    event.source = source;

    bpf_map_update_elem(&incomplete_creates, &pid_tgid, &event, BPF_ANY);
    return;

    EventMismatch:
    fm.type = FM_WARNING;
    fm.u.warning.pid_tgid = pid_tgid;
    fm.u.warning.message_type.file = FM_CREATE;
    fm.u.warning.code = W_PID_TGID_MISMATCH;
    fm.u.warning.info.stored_pid_tgid = event.pid_tgid;

    push_file_message(ctx, &fm);
    return;

    EmitWarning:
    push_file_warning(ctx, &fm, FM_CREATE);

    NoEvent:
    return;
}

static __always_inline void exit_symlink(struct pt_regs *ctx)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    file_message_t *fm = (file_message_t *)buffer;
    cursor_t cursor = { .buffer = buffer, .offset = &fm->u.action.buffer_len };
    int ret = 0;
    error_info_t info = {0};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_creates, pid_tgid, incomplete_create_t);

    if (cached_path->next_dentry != NULL) {
        goto ResolveTarget;
    }

    if (event.target_dentry == NULL || event.target_vfsmount == NULL) goto NoEvent;

    // not using read_field_ptr because we expect that `inode` could
    // be NULL in overlayfs as it gets called twice (recursively) and
    // the first time it exits it does not yet have an inode.
    void *d_inode = NULL;
    ret = read_field(event.target_dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
    if (ret < 0) goto EmitWarning;
    if (d_inode == NULL) goto NoEvent;

    ret = file_and_owner_from_ino(d_inode, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_CREATE;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.create.source_link = LINK_SYMBOLIC;

    init_filtered_cached_path(cached_path, event.target_dentry, event.target_vfsmount);

 ResolveTarget:
    ret = write_path(ctx, cached_path, &cursor,
                     (tail_call_t){
                         .slot = EXIT_SYMLINK,
                         .table = &tail_call_table,
                     });
    if (ret < 0) goto EmitWarning;
    if (cached_path->filter_state <= 0) goto NoEvent; // Didn't match watched path filter
    write_null_char(cursor.buffer, cursor.offset);
    write_string(event.source, cursor.buffer, cursor.offset, PATH_MAX);
    push_flexible_file_message(ctx, fm, *cursor.offset);

    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;

 EventMismatch:
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:
    push_file_warning(ctx, fm, FM_CREATE);

 NoEvent:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}

static __always_inline void exit_create(void *ctx, file_link_type_t link_type)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    file_message_t *fm = (file_message_t *)buffer;
    error_info_t info = {0};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_creates, pid_tgid, incomplete_create_t);

    if (event.target_dentry == NULL || event.target_vfsmount == NULL) goto NoEvent;

    void *inode = NULL;
    if (link_type == LINK_HARD) {
        // in overlayfs (maybe also other filesystems?) the target
        // dentry we captured during the security path may not be
        // assigned an inode during hardlinks since the real dentry
        // exists elsewhere with the same inode as the source
        inode = read_field_ptr(event.source, CRC_DENTRY_D_INODE);
        if (inode == NULL) goto EmitWarning;
    } else {
        // not using read_field_ptr because we expect that `inode`
        // could be NULL for kernel pseudo filesystems such as
        // cgroupfs. We still want to error if we fail to read the
        // field; we just don't want to error for the field being NULL
        int ret = read_field(event.target_dentry, CRC_DENTRY_D_INODE, &inode, sizeof(inode));
        if (ret < 0) goto EmitWarning;
        if (inode == NULL) goto NoEvent;
    }

    int ret = file_and_owner_from_ino(inode, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_CREATE;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.create.source_link = link_type;

    init_filtered_cached_path(cached_path, event.target_dentry, event.target_vfsmount);
    if (link_type == LINK_HARD) {
        cached_path->next_path = event.source;
    }

    bpf_tail_call(ctx, &tp_programs, FILE_PATHS);

    info.tailcall = FILE_PATHS;
    set_local_warning(W_TAIL_CALL_MAX, info);
    goto EmitWarning;

 EventMismatch:
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:
    push_file_warning(ctx, fm, FM_CREATE);

 NoEvent:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}
