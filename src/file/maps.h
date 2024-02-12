#pragma once

#include "common/common.h"
#include "common/offsets.h"
#include "vmlinux.h"

#include "common/bpf_helpers.h"
#include "common/definitions.h"
#include "common/types.h"
#include "file/push_file_message.h"

struct syscalls_enter_generic_args {
    __u64 unused;
    long __syscall_nr;
    /* other args -- make custom structs if needed */
};

typedef struct {
    file_message_type_t kind;   // kind of file message
    u64 probe_id;               // ID of the probe that inserted the event
    u64 start_ktime_ns;         // when did the syscall start
    void *vfsmount;             // vfsmount of the relevant dentries
    void *target_dentry;        // dentry of the file acted on in the case of FM_RENAME this is the
                                // file being moved. During exit of the syscall, the name + parent
                                // will be the destination's name + parent
    union {
        struct {
            void *source;           // dentry for hard link, char for symlink, NULL otherwise
        } create;
        struct {
            file_ownership_t ownership; // ownership data prior to inode deletion
            file_info_t target;         // target info prior to inode deletion
        } delete;
        struct {
            file_ownership_t before_owner; // ownership data prior to any changes
            bool is_created; // if the file was created when opened
        } modify;
        struct {
            void *source_parent_dentry;         // The directory we are moving from
            file_ownership_t overwr_owner;      // The owner of the overwritten file
            file_info_t overwr;                 // Metadata of the overwritten file
            char name[NAME_MAX+1];              // Name of the overwritten file
        } rename;
    };
} incomplete_file_message_t;

// A map of file messages that have started (an enter tracepoint) but are yet to finish (the exit
// tracepoint)
struct bpf_map_def SEC("maps/incomplete_file_messages") incomplete_file_messages = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_file_message_t),
    .max_entries = 2048,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void enter_file_message(struct syscalls_enter_generic_args *ctx, file_message_type_t kind)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_file_message_t event = {0};
    event.start_ktime_ns = bpf_ktime_get_ns();
    event.kind = kind;
    event.probe_id = ctx->__syscall_nr;

    // deliberately only insert if the key does not exist -- we want
    // to be truthful if we forgot to pop so userspace knows that
    // there is a bug somewhere
    int ret = bpf_map_update_elem(&incomplete_file_messages, &pid_tgid, &event, BPF_NOEXIST);
    if (ret < 0)
    {
        file_message_t fm = {0};
        fm.type = FM_WARNING;
        fm.u.warning.probe_id = ctx->__syscall_nr;
        fm.u.warning.pid_tgid = pid_tgid;
        fm.u.warning.message_type.file = kind;
        fm.u.warning.code = W_UPDATE_MAP_ERROR;
        fm.u.warning.info.err = ret;

        push_file_message(ctx, &fm);

        // if we fail to insert delete it so that exit probes don't
        // accidentally try to use it to re-emit the event
        bpf_map_delete_elem(&incomplete_file_messages, &pid_tgid);
    }
}

static __always_inline incomplete_file_message_t *get_event(void *ctx,
                                                            file_message_type_t kind, u64 *pid_tgid, u64 probe_id) {
  incomplete_file_message_t *event = bpf_map_lookup_elem(&incomplete_file_messages, pid_tgid);
  if (event == NULL) return NULL;

  file_message_type_t stored_kind = event->kind;
  if (stored_kind != kind) {
      // emit warning
      file_message_t fm = {0};
      fm.type = FM_WARNING;
      fm.u.warning.probe_id = probe_id;
      fm.u.warning.pid_tgid = *pid_tgid;
      fm.u.warning.message_type.file = kind;
      fm.u.warning.code = W_KIND_MISMATCH;
      fm.u.warning.info.stored.kind.file = stored_kind;
      fm.u.warning.info.stored.probe_id = event->probe_id;

      push_file_message(ctx, &fm);

      // just to be safe - let's delete ourselves since it isn't what we expect. It might mean some
      // event may get lost but we'll know that from the warning
      bpf_map_delete_elem(&incomplete_file_messages, pid_tgid);

      return NULL;
  }

  return event;
}

static __always_inline incomplete_file_message_t* set_file_dentry(struct pt_regs *ctx,
                                                                  file_message_type_t kind, void *dentry, u64 probe_id)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_file_message_t *event = bpf_map_lookup_elem(&incomplete_file_messages, &pid_tgid);

    if (event == NULL) return NULL;
    if (event->target_dentry != NULL) return NULL;
    if (event->kind != kind) return NULL;

    event->target_dentry = dentry;
    return event;
}

static __always_inline incomplete_file_message_t* set_path_mnt(struct pt_regs *ctx,
                                                               incomplete_file_message_t* event, void *path, u64 probe_id)
{
    if (event == NULL) return NULL;

    event->vfsmount = read_field_ptr(path, CRC_PATH_MNT);
    if (event->vfsmount == NULL) goto EmitWarning;

    return event;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, event->kind, probe_id);
    return NULL;
}

static __always_inline void set_current_file_mnt(struct pt_regs *ctx, void *file, u64 probe_id)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_file_message_t *event = bpf_map_lookup_elem(&incomplete_file_messages, &pid_tgid);
    if (event == NULL || event->vfsmount != NULL) return;

    void *path = read_field_ptr(file, CRC_FILE_F_PATH);
    if (path == NULL) goto EmitWarning;
    set_path_mnt(ctx, event, path, probe_id);

    return;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, event->kind, probe_id);

    return;
}

// Handles the end states of a given message
// If null, do nothing
// If warning, emit the warning
// If success, tail call.
static __always_inline void finish_message(struct syscalls_exit_args *ctx, file_message_t *fm)
{
    if (fm == NULL) return;
    if (fm->type == FM_WARNING) goto EmitWarning;
    bpf_tail_call(ctx, &tp_programs, FILE_PATHS);

    // save the message type
    fm->u.warning.message_type.file = fm->type;
    error_info_t info = {0};
    info.tailcall = FILE_PATHS;
    set_local_warning(W_TAIL_CALL_MAX, info);
EmitWarning:;
    push_file_warning(ctx, fm, fm->u.warning.message_type.file, ctx->__syscall_nr);
}

#define GET_EXIT_EVENT(kind)                                            \
    u64 pid_tgid = bpf_get_current_pid_tgid();                          \
    incomplete_file_message_t *event = get_event(ctx, kind, &pid_tgid, ctx->__syscall_nr); \
    file_message_t *ret = NULL;                                         \
    if (event == NULL) goto Exit;                                       \
    if (ctx->ret < 0) goto Pop;

// Returns a file_message_event_t* and handles the popping from the incomplete map
#define POP_AND_SETUP(kind, fn)                                         \
    ({                                                                  \
        GET_EXIT_EVENT(kind)                                            \
        ret = fn(ctx, pid_tgid, event);                                 \
    Pop:;                                                               \
        bpf_map_delete_elem(&incomplete_file_messages, &pid_tgid);      \
    Exit:;                                                              \
        ret;                                                            \
    })

// Returns a file_message_event_t* and handles the popping from the incomplete map
#define POP_AND_SETUP_ARGS(kind, fn, args...)                           \
    ({                                                                  \
        GET_EXIT_EVENT(kind)                                            \
        ret = fn(ctx, pid_tgid, event, args);                           \
    Pop:;                                                               \
        bpf_map_delete_elem(&incomplete_file_messages, &pid_tgid);      \
    Exit:;                                                              \
        ret;                                                            \
    })
