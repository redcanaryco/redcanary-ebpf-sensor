#pragma once

#include "common/bpf_helpers.h"
#include "common/types.h"
#include "file/maps.h"
#include "push_file_message.h"
#include "common/path.h"
#include "dentry.h"

static __always_inline void enter_delete(void *ctx)
{
    enter_file_message(ctx, FM_DELETE);
}

static __always_inline incomplete_file_message_t* store_deleted_dentry(struct pt_regs *ctx, void *dentry)
{
    incomplete_file_message_t* event = set_file_dentry(ctx, FM_DELETE, dentry);
    if (event == NULL) return NULL;

    // After deletion dentries become "negative" dentries and no
    // longer have an inode. Furthermore, some filesystems (e.g., xfs)
    // are more aggressive about inode destruction and clear fields
    // such as file mode early
    int ret = file_from_dentry(dentry, &event->delete.target, &event->delete.ownership);
    if (ret < 0) goto EmitWarning;

    return event;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, FM_DELETE);
    return NULL;
}

static __always_inline void store_deleted_path_dentry(struct pt_regs *ctx, void *path, void *dentry)
{
    incomplete_file_message_t* event = store_deleted_dentry(ctx, dentry);
    set_path_mnt(ctx, event, path);
}

static __always_inline file_message_t* exit_delete(void *ctx, u64 pid_tgid, incomplete_file_message_t *event)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return NULL;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return NULL;

    file_message_t *fm = NULL;
    if (event->target_dentry == NULL || event->vfsmount == NULL) goto Done;

    fm = (file_message_t *)buffer;

    fm->type = FM_DELETE;
    fm->u.action.pid = pid_tgid >> 32;
    fm->u.action.mono_ns = event->start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.target = event->delete.target;
    fm->u.action.target_owner = event->delete.ownership;

    init_filtered_cached_path(cached_path, event->target_dentry, event->vfsmount);

    return fm;

 Done:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return fm;
}
