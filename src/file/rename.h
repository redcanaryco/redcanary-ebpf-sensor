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
    void *vfsmount;                     // vfsmount of the source AND the destination.
    void *source_dentry;                // dentry of the file we are
                                        // moving. By the time we exit
                                        // the name + parent will be the target name + parent
    void *source_parent_dentry;         // The directory we are moving from
    file_ownership_t overwr_owner;      // The owner of the overwritten file
    file_info_t overwr;                 // Metadata of the overwritten file
} incomplete_rename_t;

typedef struct {
    u64 pid_tgid;
    char name[NAME_MAX+1];
} rename_name_t;

struct bpf_map_def SEC("maps/incomplete_renames") incomplete_renames = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_rename_t),
    .max_entries = 512,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/rename_names") rename_names = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(rename_name_t),
    .max_entries = 512,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void enter_rename(void *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    rename_name_t rename_name = {0};
    rename_name.pid_tgid = pid_tgid;
    int ret = bpf_map_update_elem(&rename_names, &pid_tgid, &rename_name, BPF_ANY);
    if (ret < 0) goto EmitWarning;

    incomplete_rename_t event = {0};
    event.pid_tgid = pid_tgid;
    event.start_ktime_ns = bpf_ktime_get_ns();

    ret = bpf_map_update_elem(&incomplete_renames, &pid_tgid, &event, BPF_ANY);
    if (ret < 0) goto EmitWarning;

    return;

 EmitWarning:;
    file_message_t fm = {0};
    fm.type = FM_WARNING;
    fm.u.warning.pid_tgid = pid_tgid;
    fm.u.warning.message_type.file = FM_RENAME;
    fm.u.warning.code = W_UPDATE_MAP_ERROR;
    fm.u.warning.info.err = ret;

    push_file_message(ctx, &fm);
}

static __always_inline void store_renamed_dentries(struct pt_regs *ctx,
                                                   void *old_dir, void *old_dentry,
                                                   void *new_dir, void *new_dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    file_message_t fm = {0};

    load_event(incomplete_renames, pid_tgid, incomplete_rename_t);
    if (event.source_dentry != NULL) goto NoEvent;

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

    event.vfsmount = read_field_ptr(new_dir, CRC_PATH_MNT);
    if (event.vfsmount == NULL) goto EmitWarning;

    // if the new_dentry already has an inode it means that we are replacing it
    // TODO: what about whiteouts? Will they have an inode?
    void *d_inode = NULL;
    ret = read_field(new_dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
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

    if (event.source_dentry == NULL || event.vfsmount == NULL) goto NoEvent;

    void *d_inode = NULL;
    int ret = read_field(event.source_dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
    if (ret < 0) goto EmitWarning;
    if (d_inode != NULL) {
        ret = extract_file_info_owner(d_inode, &fm->u.action.target, &fm->u.action.target_owner);
        if (ret < 0) goto EmitWarning;
    } else {
        // if the target dentry has no inode it means that it was either deleted or not set.
        // zero out the file_info and file_ownership to indicate that but submit the event anyway
        // only if it is a filtered path and handle it in userspace
        file_info_t blank_info = {0};
        file_ownership_t blank_owner = {0};
        fm->u.action.target = blank_info;
        fm->u.action.target_owner = blank_owner;
    }

    fm->type = FM_RENAME;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.rename.overwr = event.overwr;
    fm->u.action.u.rename.overwr_owner = event.overwr_owner;

    init_filtered_cached_path(cached_path, event.source_dentry, event.vfsmount);
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
