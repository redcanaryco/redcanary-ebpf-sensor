#pragma once

#include "common/bpf_helpers.h"
#include "common/common.h"
#include "common/offsets.h"
#include "common/path.h"
#include "common/types.h"
#include "dentry.h"
#include "file/maps.h"
#include "push_file_message.h"

static __always_inline void enter_create(void *ctx)
{
    enter_file_message(ctx, FM_CREATE);
}

// The source parameter should be NULL if there is no source, a dentry for hard links, or a char * for symlink
static __always_inline void store_dentry(struct pt_regs *ctx, void *path, void *dentry, void *source)
{
    incomplete_file_message_t* event = set_file_path(ctx, FM_CREATE, path, dentry);
    if (event == NULL) return;

    event->create.source = source;
    return;
}

static __always_inline void _exit_symlink(struct pt_regs *ctx, u64 pid_tgid, incomplete_file_message_t *event)
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

    if (event->target_dentry == NULL || event->vfsmount == NULL) goto NoEvent;

    // not using read_field_ptr because we expect that `inode` could
    // be NULL in overlayfs as it gets called twice (recursively) and
    // the first time it exits it does not yet have an inode.
    void *d_inode = NULL;
    ret = read_field(event->target_dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
    if (ret < 0) goto EmitWarning;
    if (d_inode == NULL) goto NoEvent;

    ret = file_and_owner_from_ino(d_inode, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_CREATE;
    fm->u.action.pid = pid_tgid >> 32;
    fm->u.action.mono_ns = event->start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.create.source_link = LINK_SYMBOLIC;

    init_filtered_cached_path(cached_path, event->target_dentry, event->vfsmount);

 ResolveTarget:
    ret = write_path(ctx, cached_path, &cursor,
                     (tail_call_t){
                         .slot = EXIT_SYMLINK,
                         .table = &tail_call_table,
                     });
    if (ret < 0) goto EmitWarning;
    if (cached_path->filter_state <= 0) goto NoEvent; // Didn't match watched path filter
    write_null_char(cursor.buffer, cursor.offset);
    write_string(event->create.source, cursor.buffer, cursor.offset, PATH_MAX);
    push_flexible_file_message(ctx, fm, *cursor.offset);

    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;

 EmitWarning:
    push_file_warning(ctx, fm, FM_CREATE);

 NoEvent:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}

static __always_inline file_message_t* exit_create(void *ctx, u64 pid_tgid, incomplete_file_message_t *event, file_link_type_t link_type)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return NULL;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return NULL;

    file_message_t *fm = NULL;
    if (event->target_dentry == NULL || event->vfsmount == NULL) goto Done;

    fm = (file_message_t *)buffer;
    fm->type = FM_CREATE;

    void *inode = NULL;
    int ret = 0;
    if (link_type == LINK_HARD) {
        // in overlayfs (maybe also other filesystems?) the target
        // dentry we captured during the security path may not be
        // assigned an inode during hardlinks since the real dentry
        // exists elsewhere with the same inode as the source
        ret = file_from_dentry(event->create.source, &fm->u.action.target, &fm->u.action.target_owner);
    } else {
        // `inode` could be NULL for kernel pseudo filesystems such as
        // cgroupfs. We don't care about these filesystems so skip if
        // inode is NULL. There may be false negatives here (inodes
        // being NULL for other reasons) but in our testing we have
        // only ever triggered this from cgroupfs
        ret = read_field(event->target_dentry, CRC_DENTRY_D_INODE, &inode, sizeof(inode));
        if (ret < 0) goto EmitWarning;
        if (inode == NULL) goto NoEvent;
        ret = file_and_owner_from_ino(inode, &fm->u.action.target, &fm->u.action.target_owner);
    }

    if (ret < 0) goto EmitWarning;

    fm->u.action.pid = pid_tgid >> 32;
    fm->u.action.mono_ns = event->start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.create.source_link = link_type;

    init_filtered_cached_path(cached_path, event->target_dentry, event->vfsmount);
    if (link_type == LINK_HARD) {
        cached_path->next_path = event->create.source;
    }

    return fm;

 NoEvent:
    fm = NULL;
    goto Done;

 EmitWarning:
    fm->u.warning.message_type.file = fm->type;
    fm->type = FM_WARNING;

 Done:
    // reset next_dentry for this CPU
    cached_path->next_dentry = NULL;
    return fm;
}
