#pragma once

#include "common/common.h"
#include "common/offsets.h"
#include "vmlinux.h"

#include "common/bpf_helpers.h"
#include "common/definitions.h"
#include "common/types.h"
#include "file/push_file_message.h"

typedef struct {
    file_message_type_t kind;   // kind of file message
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
    };
} incomplete_file_message_t;

// A map of file messages that have started (an enter tracepoint) but are yet to finish (the exit
// tracepoint)
struct bpf_map_def SEC("maps/incomplete_file_messages") incomplete_file_messages = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(incomplete_file_message_t),
    .max_entries = 1536,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void enter_file_message(void *ctx, file_message_type_t kind)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    incomplete_file_message_t event = {0};
    event.start_ktime_ns = bpf_ktime_get_ns();
    event.kind = kind;

    int ret = bpf_map_update_elem(&incomplete_file_messages, &pid_tgid, &event, BPF_ANY);
    if (ret < 0)
    {
        file_message_t fm = {0};
        fm.type = FM_WARNING;
        fm.u.warning.pid_tgid = pid_tgid;
        fm.u.warning.message_type.file = kind;
        fm.u.warning.code = W_UPDATE_MAP_ERROR;
        fm.u.warning.info.err = ret;

        push_file_message(ctx, &fm);
    }
}

static __always_inline incomplete_file_message_t* get_event(file_message_type_t kind, u64 *pid_tgid) {
  incomplete_file_message_t *event = bpf_map_lookup_elem(&incomplete_file_messages, pid_tgid);
  if (event == NULL) return NULL;

  if (event->kind != kind) {
    // TODO: emit warning
    bpf_map_delete_elem(&incomplete_file_messages, pid_tgid);
    return NULL;
  }

  return event;
}

static __always_inline incomplete_file_message_t* get_current_event(file_message_type_t kind) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  return get_event(kind, &pid_tgid);
}

static __always_inline incomplete_file_message_t* set_file_path(struct pt_regs *ctx, file_message_type_t kind,
                                                         void *path, void *dentry)
{
    incomplete_file_message_t* event = get_current_event(kind);
    if (event == NULL) return NULL;
    if (event->target_dentry != NULL) return NULL;

    event->target_dentry = dentry;
    event->vfsmount = read_field_ptr(path, CRC_PATH_MNT);
    if (event->vfsmount == NULL) goto EmitWarning;

    return event;

 EmitWarning:;
    file_message_t fm = {0};
    push_file_warning(ctx, &fm, event->kind);
    return NULL;
}

static __always_inline void handle_message(void *ctx, file_message_t *fm)
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
    push_file_warning(ctx, fm, fm->u.warning.message_type.file);
}

#define GET_EXIT_EVENT(kind)                                            \
    u64 pid_tgid = bpf_get_current_pid_tgid();                          \
    incomplete_file_message_t *event = get_event(kind, &pid_tgid);      \
    file_message_t *ret = NULL;                                         \
    if (event == NULL) goto Exit;                                       \
    if (ctx->ret < 0) goto Pop;

#define POP_AND_SETUP(kind, fn)                                         \
    ({                                                                  \
        GET_EXIT_EVENT(kind)                                            \
        ret = fn(ctx, pid_tgid, event);                                 \
    Pop:;                                                               \
        bpf_map_delete_elem(&incomplete_file_messages, &pid_tgid);      \
    Exit:;                                                              \
        ret;                                                            \
    })

#define POP_AND_SETUP_ARGS(kind, fn, args...)                           \
    ({                                                                  \
        GET_EXIT_EVENT(kind)                                            \
        ret = fn(ctx, pid_tgid, event, args);                           \
    Pop:;                                                               \
        bpf_map_delete_elem(&incomplete_file_messages, &pid_tgid);      \
    Exit:;                                                              \
        ret;                                                            \
    })
