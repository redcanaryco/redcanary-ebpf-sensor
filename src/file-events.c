// SPDX-License-Identifier: GPL-2.0+

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/fs.h>
#include "bpf_helpers.h"
#include "types.h"
#include "offsets.h"
#include "common.h"
#include "process/helpers.h"
#include "process/buffer.h"
#include "process/path.h"
#include "process/warning.h"

// The map where process event messages get emitted to
struct bpf_map_def SEC("maps/file_events") file_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

// pushes a message to the file_events perfmap for the current CPU.
static __always_inline int push_file_message(struct pt_regs *ctx, file_message_t *fm)
{
    return bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, fm, sizeof(*fm));
}

// pushes a message with an extra `dynamic_size` number of bytes. It
// will never send more than `MAX_PERCPU_BUFFER` number of bytes. It
// is a *bug* if dynamic_size here is larger than MAX_PERCPU_BUFFER
// and it will cause the number of bytes to to dynamic_size %
// MAX_PERCPU_BUFFER.
static __always_inline int push_flexible_file_message(struct pt_regs *ctx, file_message_t *ev, u64 dynamic_size)
{
    // The -1 and +1 logic is here to prevent a buffer that is exactly
    // MAX_PERCPU_BUFFER size to become 0 due to the bitwise AND. We
    // know that dynamic_size will never be 0 so this is safe.
    u64 size_to_send = ((dynamic_size - 1) & (MAX_PERCPU_BUFFER - 1)) + 1;
    return bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, ev, size_to_send);
}

// pushes a warning to the process_events perfmap for the current CPU.
static __always_inline int push_file_warning(struct pt_regs *ctx, file_message_t *fm,
                                             file_message_type_t fm_type)
{
    fm->type = FM_WARNING;
    message_type_t m_type;
    m_type.file = fm_type;

    load_warning_info(&fm->u.warning, m_type);

    return push_file_message(ctx, fm);
}

// its argument should be a pointer to a dentry
static __always_inline int extract_file_info_owner(void *ptr, file_info_t *file_info, file_ownership_t *file_owner)
{
    void *d_inode = read_field_ptr(ptr, CRC_DENTRY_D_INODE);
    if (d_inode == NULL) return -1;

    void *i_sb = read_field_ptr(d_inode, CRC_INODE_I_SB);
    if (i_sb == NULL) return -1;

    // inode
    if (read_field(d_inode, CRC_INODE_I_INO, &file_info->inode, sizeof(file_info->inode)) < 0)
        return -1;

    // device major/minor
    u32 i_dev = 0;
    if (read_field(i_sb, CRC_SBLOCK_S_DEV, &i_dev, sizeof(i_dev)) < 0) return -1;

    file_info->devmajor = MAJOR(i_dev);
    file_info->devminor = MINOR(i_dev);

    // uid/gid/mode
    if (read_field(d_inode, CRC_INODE_I_UID, &file_owner->uid, sizeof(file_owner->uid)) < 0)
        return -1;
    if (read_field(d_inode, CRC_INODE_I_GID, &file_owner->gid, sizeof(file_owner->gid)) < 0)
        return -1;
    if (read_field(d_inode, CRC_INODE_I_MODE, &file_owner->mode, sizeof(file_owner->mode)) < 0)
        return -1;

    return 0;
}

typedef struct {
  u64 pid_tgid;
  u64 start_ktime_ns;
  void *target_dentry;
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

        return;
    }

    return;
}

static __always_inline void store_dentry(struct pt_regs *ctx, void *dentry)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    load_event(incomplete_mkdirs, pid_tgid, incomplete_mkdir_t);
    if (event.target_dentry == NULL)
        event.target_dentry = dentry;
    bpf_map_update_elem(&incomplete_mkdirs, &pid_tgid, &event, BPF_ANY);
    return;

    EventMismatch:;
    file_message_t fm = {0};
    fm.type = FM_WARNING;
    fm.u.warning.pid_tgid = pid_tgid;
    fm.u.warning.message_type.file = FM_CREATE;
    fm.u.warning.code = W_PID_TGID_MISMATCH;
    fm.u.warning.info.stored_pid_tgid = event.pid_tgid;

    push_file_message(ctx, &fm);
    return;

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
    ret = extract_file_info_owner(event.target_dentry, &fm->u.action.target, &fm->u.action.target_owner);
    if (ret < 0) goto EmitWarning;

    fm->type = FM_CREATE;
    fm->u.action.pid = event.pid_tgid >> 32;
    fm->u.action.mono_ns = event.start_ktime_ns;
    fm->u.action.buffer_len = sizeof(file_message_t);
    fm->u.action.u.create.source_link = LINK_NONE;

    cached_path->next_dentry = event.target_dentry;

    ResolveName:
    ret = write_path(ctx, cached_path, &cursor, tail_call);
    cached_path->next_dentry = NULL;
    if (ret < 0) goto EmitWarning;

    write_null_char(cursor.buffer, cursor.offset);
    push_flexible_file_message(ctx, fm, *cursor.offset);
    return;

    EventMismatch:
    info.stored_pid_tgid = event.pid_tgid;
    set_local_warning(W_PID_TGID_MISMATCH, info);

    EmitWarning:
    push_file_warning(ctx, fm, FM_CREATE);
    return;

    NoEvent:
    return;
}

SEC("kprobe/sys_mkdir")
int BPF_KPROBE_SYSCALL(kprobe__sys_mkdir) {
    enter_mkdir(ctx);
    return 0;
}

SEC("kprobe/sys_mkdirat")
int BPF_KPROBE_SYSCALL(kprobe__sys_mkdirat) {
    enter_mkdir(ctx);
    return 0;
}
SEC("kprobe/security_inode_mkdir")
int BPF_KPROBE(security_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode) {
    store_dentry(ctx, (void *)dentry);
    return 0;
}

SEC("kretprobe/ret_do_mkdirat")
int BPF_KRETPROBE(do_mkdirat, int retval) {
    if (retval < 0) return 0;
    exit_mkdir(ctx, RET_DO_MKDIRAT);
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;