#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/helpers.h"
#include "common/offsets.h"
#include "common/types.h"
#include "push_file_message.h"
#include "common/path.h"
#include "dentry.h"

typedef struct {
    u64 pid_tgid;
    u64 start_ktime_ns;
    void *target_vfsmount;  // vfsmount of the containing directory
    void *target_dentry;    // dentry of the removed object
    void *target_inode;     // inode of the removed object
} incomplete_delete_t;

struct bpf_map_def SEC("maps/incomplete_deletes") incomplete_deletes = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_delete_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void enter_delete(void *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_delete_t event = {0};
    event.pid_tgid = pid_tgid;
    event.start_ktime_ns = bpf_ktime_get_ns();

    int ret = bpf_map_update_elem(&incomplete_deletes, &pid_tgid, &event, BPF_ANY);
    if (ret < 0)
        {
            file_message_t fm = {0};
            fm.type = FM_WARNING;
            fm.u.warning.pid_tgid = pid_tgid;
            fm.u.warning.message_type.file = FM_DELETE;
            fm.u.warning.code = W_UPDATE_MAP_ERROR;
            fm.u.warning.info.err = ret;

            push_file_message(ctx, &fm);
        }
}

static __always_inline void store_deleted_dentry(struct pt_regs *ctx, void *path, void *dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    file_message_t fm = {0};

    load_event(incomplete_deletes, pid_tgid, incomplete_delete_t);
    if (event.target_dentry != NULL) goto NoEvent;

    event.target_dentry = dentry;
    event.target_vfsmount = read_field_ptr(path, CRC_PATH_MNT);
    if (event.target_vfsmount == NULL) goto EmitWarning;
    // After deletion dentries become "negative" dentries and no
    // longer have an inode
    event.target_inode = read_field_ptr(dentry, CRC_DENTRY_D_INODE);
    if (event.target_inode == NULL) goto EmitWarning;

    bpf_map_update_elem(&incomplete_deletes, &pid_tgid, &event, BPF_ANY);
    return;

 EventMismatch:
    fm.type = FM_WARNING;
    fm.u.warning.pid_tgid = pid_tgid;
    fm.u.warning.message_type.file = FM_DELETE;
    fm.u.warning.code = W_PID_TGID_MISMATCH;
    fm.u.warning.info.stored_pid_tgid = event.pid_tgid;

    push_file_message(ctx, &fm);
    return;

 EmitWarning:
    push_file_warning(ctx, &fm, FM_DELETE);

 NoEvent:
    return;
}

static __always_inline void exit_delete(void *ctx)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    file_message_t *fm = (file_message_t *)buffer;
    cursor_t cursor = { .buffer = buffer, .offset = &fm->u.action.buffer_len };
    int ret = 0;

    if (cached_path->next_dentry != NULL) {
        goto ResolveTarget;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_deletes, pid_tgid, incomplete_delete_t);
    error_info_t info = {0};

    if (event.target_dentry == NULL || event.target_vfsmount == NULL) {
        set_empty_local_warning(W_NO_DENTRY);
        goto EmitWarning;
    }

    ret = extract_file_info_owner(event.target_inode, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_DELETE;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);

    init_filtered_cached_path(cached_path, event.target_dentry, event.target_vfsmount);

 ResolveTarget:
    ret = write_path(ctx, cached_path, &cursor, (tail_call_t){
            .slot = EXIT_DELETE,
            .table = &tp_programs,
        });
    if (ret < 0) goto EmitWarning;
    fm->u.action.tag = (cached_path->filter_state >= 0) ? cached_path->filter_tag : -1;
    if (cached_path->filter_state <= 0) goto NoEvent; // Didn't match watched path filter

    push_flexible_file_message(ctx, fm, *cursor.offset);

    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;

 EventMismatch:
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:
    push_file_warning(ctx, fm, FM_DELETE);

 NoEvent:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}
