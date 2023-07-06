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
    void *target_vfsmount;      // vfsmount of the containing directory
    void *target_dentry;        // dentry of the removed object
    file_ownership_t ownership; // ownership data prior to inode deletion
    file_info_t target;         // target info prior to inode deletion
} incomplete_delete_t;

struct bpf_map_def SEC("maps/incomplete_deletes") incomplete_deletes = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_delete_t),
    .max_entries = 512,
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
    // longer have an inode. Furthermore, some filesystems (e.g., xfs)
    // are more aggressive about inode destruction and clear fields
    // such as file mode early
    void *d_inode = read_field_ptr(dentry, CRC_DENTRY_D_INODE);
    if (d_inode == NULL) goto EmitWarning;
    int ret = extract_file_info_owner(d_inode, &event.target, &event.ownership);
    if (ret < 0) goto EmitWarning;

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
    error_info_t info = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_deletes, pid_tgid, incomplete_delete_t);

    if (event.target_dentry == NULL || event.target_vfsmount == NULL) {
        set_empty_local_warning(W_NO_DENTRY);
        goto EmitWarning;
    }

    fm->type = FM_DELETE;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.target = event.target;
    fm->u.action.target_owner = event.ownership;

    init_filtered_cached_path(cached_path, event.target_dentry, event.target_vfsmount);

    bpf_tail_call(ctx, &tp_programs, FILE_PATHS);

    info.tailcall = FILE_PATHS;
    set_local_warning(W_TAIL_CALL_MAX, info);
    goto EmitWarning;

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
