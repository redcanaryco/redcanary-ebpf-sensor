#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/helpers.h"
#include "common/offsets.h"
#include "common/path.h"
#include "common/types.h"
#include "common/warning.h"
#include "dentry.h"
#include "push_file_message.h"

typedef struct {
    u64 pid_tgid;
    u64 start_ktime_ns;
    void *target_vfsmount;
    void *target_dentry;
    void *source_dentry;
    void *source_parent_dentry;
    file_ownership_t overwr_owner;
    file_info_t overwr;
} incomplete_rename_t;

typedef struct {
    u64 pid_tgid;
    char name[NAME_MAX+1];
} rename_name_t;

struct bpf_map_def SEC("maps/incomplete_renames") incomplete_renames = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_rename_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/incomplete_renames") rename_names = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(rename_name_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void enter_rename(void *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    rename_name_t rename_name = {0};
    rename_name.pid_tgid = pid_tgid;
    bpf_map_update_elem(&rename_names, &pid_tgid, &rename_name, BPF_ANY);
    incomplete_rename_t event = {0};
    event.pid_tgid = pid_tgid;
    event.start_ktime_ns = bpf_ktime_get_ns();

    int ret = bpf_map_update_elem(&incomplete_renames, &pid_tgid, &event, BPF_ANY);
    if (ret < 0)
        {
            file_message_t fm = {0};
            fm.type = FM_WARNING;
            fm.u.warning.pid_tgid = pid_tgid;
            fm.u.warning.message_type.file = FM_RENAME;
            fm.u.warning.code = W_UPDATE_MAP_ERROR;
            fm.u.warning.info.err = ret;

            push_file_message(ctx, &fm);
        }
}

static __always_inline void store_renamed_dentries(struct pt_regs *ctx,
                                                   void *old_dir, void *old_dentry,
                                                   void *new_dir, void *new_dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    file_message_t fm = {0};

    load_event(incomplete_renames, pid_tgid, incomplete_rename_t);
    if (event.target_dentry != NULL) goto NoEvent;

    event.target_dentry = new_dentry;
    event.source_dentry = old_dentry;
    event.source_parent_dentry = read_field_ptr(old_dentry, CRC_DENTRY_D_PARENT);
    if (event.source_parent_dentry == NULL) goto EmitWarning;
    void *source_name = ptr_to_field(old_dentry, CRC_DENTRY_D_NAME);
    if (source_name == NULL) goto EmitWarning;
    source_name = read_field_ptr(source_name, CRC_QSTR_NAME);
    if (source_name == NULL) goto EmitWarning;
    rename_name_t *name = bpf_map_lookup_elem(&rename_names, &pid_tgid);
    if (name == NULL) goto NoEvent;
    if (name->pid_tgid != pid_tgid) goto EventMismatch;

    int ret = bpf_probe_read_str(&name->name, sizeof(name->name), source_name);
    if (ret < 0) {
        set_empty_local_warning(W_READ_PATH_STRING);
        goto EmitWarning;
    }

    event.target_vfsmount = read_field_ptr(new_dir, CRC_PATH_MNT);
    if (event.target_vfsmount == NULL) goto EmitWarning;

    // if the new_dentry already has an inode it means that we are replacing it
    // TODO: what about whiteouts? Will they have an inode?
    void *d_inode = NULL;
    ret = read_field(event.target_dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
    if (ret < 0) goto EmitWarning;
    if (d_inode != NULL) {
        ret = extract_file_info_owner(d_inode, &event.overwr, &event.overwr_owner);
        if (ret < 0) goto EmitWarning;
    }

    bpf_map_update_elem(&incomplete_renames, &pid_tgid, &event, BPF_ANY);
    return;

 EventMismatch:
    fm.type = FM_WARNING;
    fm.u.warning.pid_tgid = pid_tgid;
    fm.u.warning.message_type.file = FM_RENAME;
    fm.u.warning.code = W_PID_TGID_MISMATCH;
    fm.u.warning.info.stored_pid_tgid = event.pid_tgid;

    push_file_message(ctx, &fm);
    return;

 EmitWarning:
    push_file_warning(ctx, &fm, FM_RENAME);

 NoEvent:
    return;
}

static __always_inline void exit_rename(void *ctx)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    file_message_t *fm = (file_message_t *)buffer;
    error_info_t info = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_renames, pid_tgid, incomplete_rename_t);

    if (event.target_dentry == NULL || event.target_vfsmount == NULL) {
        set_empty_local_warning(W_NO_DENTRY);
        goto EmitWarning;
    }

    void *d_inode = read_field_ptr(event.source_dentry, CRC_DENTRY_D_INODE);
    if (d_inode == NULL) goto EmitWarning;
    int ret = extract_file_info_owner(d_inode, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_RENAME;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.rename.overwr = event.overwr;
    fm->u.action.u.rename.overwr_owner = event.overwr_owner;

    init_filtered_cached_path(cached_path, event.target_dentry, event.target_vfsmount);
    cached_path->next_path = event.source_parent_dentry;

    bpf_tail_call(ctx, &tp_programs, FILE_PATHS);

    info.tailcall = FILE_PATHS;
    set_local_warning(W_TAIL_CALL_MAX, info);
    goto EmitWarning;

 EventMismatch:
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(W_PID_TGID_MISMATCH, info);

 EmitWarning:
    push_file_warning(ctx, fm, FM_RENAME);

 NoEvent:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}