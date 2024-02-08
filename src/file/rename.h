#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/offsets.h"
#include "common/path.h"
#include "common/types.h"
#include "common/warning.h"
#include "dentry.h"
#include "file/maps.h"
#include "push_file_message.h"

// used for events with flexible sizes (i.e., exec*) so it can send
// extra data. Used in conjuction with a map such that it does not use
// the stack size limit.
typedef struct
{
    char name[NAME_MAX + 1];
} rename_name_t;

// A per cpu buffer that can hold more data than allowed in the
// stack. Used to collect data of variable length such as a string.
struct bpf_map_def SEC("maps/rename_names") rename_names = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(rename_name_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

static __always_inline incomplete_file_message_t*  store_renamed_dentries(struct pt_regs *ctx,
                                                                          void *old_dentry, void *new_dentry, u64 probe_id)
{
    incomplete_file_message_t* event = set_file_dentry(ctx, FM_RENAME, old_dentry, probe_id);
    if (event == NULL) return NULL;

    event->rename.source_parent_dentry = read_field_ptr(old_dentry, CRC_DENTRY_D_PARENT);
    if (event->rename.source_parent_dentry == NULL) goto EmitWarning;
    void *source_name = ptr_to_field(old_dentry, CRC_DENTRY_D_NAME);
    if (source_name == NULL) goto EmitWarning;
    source_name = read_field_ptr(source_name, CRC_QSTR_NAME);
    if (source_name == NULL) goto EmitWarning;

    int ret = bpf_probe_read_kernel_str(&event->rename.name, sizeof(event->rename.name), source_name);
    if (ret < 0) {
        set_empty_local_warning(W_READ_PATH_STRING);
        goto EmitWarning;
    }

    // if the new_dentry already has an inode it means that we are replacing it
    // TODO: what about whiteouts? Will they have an inode?
    void *d_inode = NULL;
    ret = read_field(new_dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
    if (ret < 0) goto EmitWarning;
    if (d_inode != NULL) {
        ret = file_and_owner_from_ino(d_inode, &event->rename.overwr, &event->rename.overwr_owner);
        if (ret < 0) goto EmitWarning;
    }

    return event;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, FM_RENAME, probe_id);
    return NULL;
}

static __always_inline void store_renamed_path_dentries(struct pt_regs *ctx,
                                                   void *old_dir, void *old_dentry,
                                                   void *new_dir, void *new_dentry, u64 probe_id)
{
    incomplete_file_message_t* event = store_renamed_dentries(ctx, old_dentry, new_dentry, probe_id);
    set_path_mnt(ctx, event, new_dir, probe_id);
}

static __always_inline file_message_t* exit_rename(void *ctx, u64 pid_tgid, incomplete_file_message_t *event)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return NULL;

    rename_name_t *rename_name = (rename_name_t *)bpf_map_lookup_elem(&rename_names, &key);
    if (rename_name == NULL) return NULL;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return NULL;

    file_message_t *fm = NULL;
    if (event->target_dentry == NULL || event->vfsmount == NULL) goto Done;

    fm = (file_message_t *)buffer;
    fm->type = FM_RENAME;

    // What we want is to copy the name from the incomplete event into the per-cpu map (to be
    // processed later via a tail-call). However, passing map values to map helpers is only allowed
    // in v4.18+:
    // https://github.com/torvalds/linux/commit/d71962f3e627b5941804036755c844fabfb65ff5. Use a
    // stack variable as in between layer to make the copy happy in older kernels (incomplete map ->
    // stack -> per cpu map).
    rename_name_t name = {0};
    int ret = bpf_probe_read_kernel_str(&name.name, sizeof(name.name), &event->rename.name);
    if (ret < 0) {
        set_empty_local_warning(W_READ_PATH_STRING);
        goto EmitWarning;
    }
    ret = bpf_probe_read_kernel_str(&rename_name->name, sizeof(rename_name->name), &name.name);
    if (ret < 0) {
        set_empty_local_warning(W_READ_PATH_STRING);
        goto EmitWarning;
    }

    ret = file_from_dentry(event->target_dentry, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->u.action.pid = pid_tgid >> 32;
    fm->u.action.mono_ns = event->start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.rename.overwr = event->rename.overwr;
    fm->u.action.u.rename.overwr_owner = event->rename.overwr_owner;

    init_filtered_cached_path(cached_path, event->target_dentry, event->vfsmount);
    cached_path->next_path = event->rename.source_parent_dentry;

    return fm;

 EmitWarning:
    fm->u.warning.message_type.file = fm->type;
    fm->type = FM_WARNING;

 Done:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return fm;
}
