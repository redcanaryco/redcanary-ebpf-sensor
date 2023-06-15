#pragma once

#include "push_file_message.h"
#include "dentry.h"
#include "common/path.h"

typedef struct {
  u64 pid_tgid;
  u64 start_ktime_ns;
  void *target_vfsmount;  // vfsmount of the containing directory
  void *target_dentry;    // dentry of the new directory
} incomplete_mkdir_t;

// A map of mkdirs that have started (a kprobe) but are yet to finish
// (the kretprobe).
struct bpf_map_def SEC("maps/incomplete_mkdir") incomplete_mkdirs = {
  .type = BPF_MAP_TYPE_LRU_HASH,
  .key_size = sizeof(u64),
  .value_size = sizeof(incomplete_mkdir_t),
  .max_entries = 256,
  .pinning = 0,
  .namespace = "",
};

static __always_inline void enter_mkdir(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_mkdir_t event = {0};
    event.pid_tgid = pid_tgid;
    event.start_ktime_ns = bpf_ktime_get_ns();

    int ret = bpf_map_update_elem(&incomplete_mkdirs, &pid_tgid, &event, BPF_ANY);
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

static __always_inline void store_dentry(struct pt_regs *ctx, void *path, void *dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    file_message_t fm = {0};

    load_event(incomplete_mkdirs, pid_tgid, incomplete_mkdir_t);
    if (event.target_dentry == NULL) {
        event.target_dentry = dentry;
        event.target_vfsmount = read_field_ptr(path, CRC_PATH_MNT);
        if (event.target_vfsmount == NULL) goto EmitWarning;
        bpf_map_update_elem(&incomplete_mkdirs, &pid_tgid, &event, BPF_ANY);
    }
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

static __always_inline void exit_mkdir(struct pt_regs *ctx, tail_call_slot_t tail_call)
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

    if (cached_path->next_dentry != NULL) goto ResolveName;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    load_event(incomplete_mkdirs, pid_tgid, incomplete_mkdir_t);
    if (event.target_dentry == NULL || event.target_vfsmount == NULL) {
        set_empty_local_warning(W_NO_DENTRY);
        goto EmitWarning;
    }
    ret = extract_file_info_owner(event.target_dentry, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_CREATE;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.create.source_link = LINK_NONE;

    init_filtered_cached_path(cached_path, event.target_dentry, event.target_vfsmount);

    ResolveName:
    ret = write_path(ctx, cached_path, &cursor, tail_call);
    if (ret < 0) goto EmitWarning;
    if (cached_path->filter_state <= 0) goto NoEvent; // Didn't match watched path filter

    fm->u.action.tag = cached_path->filter_tag;
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
