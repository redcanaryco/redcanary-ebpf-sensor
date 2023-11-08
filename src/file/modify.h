#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/path.h"
#include "common/types.h"
#include "file/dentry.h"
#include "file/maps.h"
#include "push_file_message.h"

static __always_inline void enter_modify(void *ctx)
{
    enter_file_message(ctx, FM_MODIFY);
}

// This method is called when a file is created by passing through security_path_mknod. It stores the dentry
// and vfsmount of the created file in the incomplete_modifies map with a `is_created` flag.
// If the file is created in a directory that is monitored we can reuse this information during an
// open trace to mark the open event appropriately as either a modify or create.
static __always_inline void store_open_create_dentry(struct pt_regs *ctx, void *dir, void *dentry)
{
    incomplete_file_message_t* event = set_file_path(ctx, FM_MODIFY, dir, dentry);
    if (event == NULL) return;

    event->modify.is_created = true;

    return;
 }

static __always_inline void store_modified_dentry(struct pt_regs *ctx, void *path)
{
    void *dentry = read_field_ptr(path, CRC_PATH_DENTRY);
    incomplete_file_message_t* event = set_file_path(ctx, FM_MODIFY, path, dentry);
    if (event == NULL) return;

    if (file_from_dentry(event->target_dentry, NULL, &event->modify.before_owner) < 0) {
        goto EmitWarning;
    }

    return;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, FM_MODIFY);
    return;
 }

static __always_inline file_message_t* exit_modify(void *ctx, u64 pid_tgid, incomplete_file_message_t *event)
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
