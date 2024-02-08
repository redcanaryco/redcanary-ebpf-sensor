#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/path.h"
#include "common/types.h"
#include "file/dentry.h"
#include "file/maps.h"
#include "file/open.h"
#include "push_file_message.h"

static __always_inline void maybe_enter_modify(struct syscalls_enter_generic_args *ctx, long flags)
{
    if (is_write_open(flags)) {
        enter_file_message(ctx, FM_MODIFY);
    } else {
        // if any previous message forgot to POP this pid_tgid; then we need to delete it as it is
        // no longer valid. Forgetting to delete here may trigger a warning from kind mismatch
        u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&incomplete_file_messages, &pid_tgid);
    }
}

static __always_inline incomplete_file_message_t* store_open_create_dentry(struct pt_regs *ctx, void *dentry, u64 probe_id)
{
    incomplete_file_message_t* event = set_file_dentry(ctx, FM_MODIFY, dentry, probe_id);
    if (event == NULL) return NULL;

    event->modify.is_created = true;

    return event;
}

// This method is called when a file is created by passing through security_path_mknod. It stores the dentry
// and vfsmount of the created file in the incomplete_modifies map with a `is_created` flag.
// If the file is created in a directory that is monitored we can reuse this information during an
// open trace to mark the open event appropriately as either a modify or create.
static __always_inline void store_open_create_path_dentry(struct pt_regs *ctx, void *dir, void *dentry, u64 probe_id)
{
    incomplete_file_message_t* event = store_open_create_dentry(ctx, dentry, probe_id);
    set_path_mnt(ctx, event, dir, probe_id);
}

static __always_inline incomplete_file_message_t* store_modified_dentry(struct pt_regs *ctx, void *dentry, u64 probe_id)
{
    incomplete_file_message_t* event = set_file_dentry(ctx, FM_MODIFY, dentry, probe_id);
    if (event == NULL) return NULL;

    if (file_from_dentry(event->target_dentry, NULL, &event->modify.before_owner) < 0) {
        goto EmitWarning;
    }

    return event;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, FM_MODIFY, probe_id);
    return NULL;
}

static __always_inline void store_modified_path_dentry(struct pt_regs *ctx, void *path, u64 probe_id)
{
    void *dentry = read_field_ptr(path, CRC_PATH_DENTRY);
    void *event = store_modified_dentry(ctx, dentry, probe_id);
    set_path_mnt(ctx, event, path, probe_id);
}

static __always_inline file_message_t* exit_modify(struct syscalls_exit_args *ctx, u64 pid_tgid, incomplete_file_message_t *event)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return NULL;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return NULL;

    file_message_t *fm = NULL;
    if (event->target_dentry == NULL || event->vfsmount == NULL) goto Done;

    fm = (file_message_t *)buffer;
    if (event->modify.is_created) {
        fm->type = FM_CREATE;
        fm->u.action.u.create.source_link = LINK_NONE;
    } else {
        fm->type = FM_MODIFY;
        fm->u.action.u.modify.before_owner = event->modify.before_owner;
    }

    if (file_from_dentry(event->target_dentry, &fm->u.action.target, &fm->u.action.target_owner) < 0) {
        goto EmitWarning;
    }

    fm->u.action.pid = pid_tgid >> 32;
    fm->u.action.mono_ns = event->start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);

    init_filtered_cached_path(cached_path, event->target_dentry, event->vfsmount);

    return fm;

 EmitWarning:
    fm->u.warning.message_type.file = fm->type;
    fm->type = FM_WARNING;

 Done:
    // reset next_dentry for this CPU
    cached_path->next_dentry = NULL;
    return fm;
}
