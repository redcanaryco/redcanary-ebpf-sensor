// SPDX-License-Identifier: GPL-2.0+

// Configure path.h to include filter code
#define USE_PATH_FILTER 1
// Configure path.h with maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 25

#include "vmlinux.h"

#include "common/bpf_helpers.h"
#include "common/types.h"
#include "file/create.h"
#include "file/delete.h"
#include "file/modify.h"
#include "file/rename.h"
#include "file/open.h"

/* START CREATE-LIKE PROBES */

// tail-call-only function to finish and send the symlink message
SEC("kprobe/exit_symlink")
int exit_symlink(struct pt_regs *ctx)
{
    _exit_symlink(ctx);
    return 0;
}

//
// mkdir probes
//

SEC("tracepoint/syscalls/sys_enter_mkdir")
int sys_enter_mkdir(void *ctx)
{
    enter_create(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int sys_enter_mkdirat(void *ctx)
{
    enter_create(ctx);
    return 0;
}

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(security_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
    store_dentry(ctx, (void *)dir, (void *)dentry, NULL);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int sys_exit_mkdir(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_NONE);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int sys_exit_mkdirat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_NONE);
    return 0;
}

//
// symlink probes
//

SEC("kprobe/sys_symlink")
int BPF_KPROBE_SYSCALL(sys_symlink)
{
    enter_create(ctx);
    return 0;
}

SEC("kprobe/sys_symlinkat")
int BPF_KPROBE_SYSCALL(sys_symlinkat)
{
    enter_create(ctx);
    return 0;
}

SEC("kprobe/security_path_symlink")
int BPF_KPROBE(security_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
    store_dentry(ctx, (void *)dir, (void *)dentry, (void *)old_name);
    return 0;
}

SEC("kretprobe/ret_vfs_symlink")
int BPF_KRETPROBE(ret_vfs_symlink, int retval)
{
    if (retval < 0)
        return 0;
    bpf_tail_call(ctx, &tail_call_table, EXIT_SYMLINK);
    return 0;
}

//
// hard link probes
//

SEC("tracepoint/syscalls/sys_enter_link")
int sys_enter_link(void *ctx)
{
    enter_create(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int sys_enter_linkat(void *ctx)
{
    enter_create(ctx);
    return 0;
}

SEC("kprobe/security_path_link")
int BPF_KPROBE(security_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
    store_dentry(ctx, (void *)new_dir, (void *)new_dentry, (void *)old_dentry);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int sys_exit_link(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_HARD);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_linkat")
int sys_exit_linkat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_HARD);
    return 0;
}

//
// mknod
//

SEC("tracepoint/syscalls/sys_enter_mknod")
int sys_enter_mknod(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int sys_enter_mknodat(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("kprobe/security_path_mknod")
int BPF_KPROBE(security_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
    store_open_create_dentry(ctx, (void *)dir, (void *)dentry);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknod")
int sys_exit_mknod(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mknodat")
int sys_exit_mknodat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

/* END CREATE-LIKE PROBES */

/* START DELETE-LIKE PROBES */

SEC("tracepoint/syscalls/sys_enter_unlink")
int sys_enter_unlink(void *ctx)
{
    enter_delete(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int sys_exit_unlink(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_delete(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int sys_enter_unlinkat(void *ctx)
{
    enter_delete(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int sys_exit_unlinkat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_delete(ctx);
    return 0;
}

SEC("kprobe/security_path_unlink")
int BPF_KPROBE(security_path_unlink, const struct path *dir, struct dentry *dentry)
{
    store_deleted_dentry(ctx, (void *)dir, dentry);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int sys_enter_rmdir(void *ctx)
{
    enter_delete(ctx);
    return 0;
}

SEC("kprobe/security_path_rmdir")
int BPF_KPROBE(security_path_rmdir, const struct path *dir, struct dentry *dentry)
{
    store_deleted_dentry(ctx, (void *)dir, dentry);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int sys_exit_rmdir(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_delete(ctx);
    return 0;
}

/* END DELETE-LIKE PROBES */

/* START CHMOD-LIKE */

SEC("tracepoint/syscalls/sys_enter_chmod")
int sys_enter_chmod(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int sys_exit_chmod(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int sys_enter_fchmod(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int sys_exit_fchmod(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int sys_enter_fchmodat(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchmodat")
int sys_exit_fchmodat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("kprobe/security_path_chmod")
int BPF_KPROBE(security_path_chmod, const struct path *path, umode_t mode)
{
    store_modified_dentry(ctx, (void *)path);
    return 0;
}

/* END CHMOD-LIKE PROBES */

/* START CHOWN-LIKE */

SEC("tracepoint/syscalls/sys_enter_chown")
int sys_enter_chown(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_chown")
int sys_exit_chown(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int sys_enter_lchown(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_lchown")
int sys_exit_lchown(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int sys_enter_fchown(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int sys_exit_fchown(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int sys_enter_fchownat(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fchownat")
int sys_exit_fchownat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("kprobe/security_path_chown")
int BPF_KPROBE(security_path_chown, const struct path *path, uid_t uid, gid_t gid)
{
    store_modified_dentry(ctx, (void *)path);
    return 0;
}

/* END CHOWN-LIKE PROBES */

/* START RENAME PROBES */

SEC("tracepoint/syscalls/sys_enter_rename")
int sys_enter_rename(void *ctx)
{
    enter_rename(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int sys_exit_rename(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_rename(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int sys_enter_renameat(void *ctx)
{
    enter_rename(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int sys_exit_renameat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_rename(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int sys_enter_renameat2(void *ctx)
{
    enter_rename(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int sys_exit_renameat2(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_rename(ctx);
    return 0;
}

SEC("kprobe/security_path_rename")
int BPF_KPROBE(security_path_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
    store_renamed_dentries(ctx, (void *)old_dir, old_dentry, (void *)new_dir, new_dentry);
    return 0;
}

/* END RENAME PROBES */
/* BEGIN OPEN-LIKE PROBES */

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx)
{
    if (is_write_open(ctx->flags)) {
        enter_modify(ctx);
        return 0;
    }
    u64 pid_tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&incomplete_modifies, &pid_tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscalls_enter_openat_args *ctx)
{
    if (is_write_open(ctx->flags)) {
        enter_modify(ctx);
        return 0;
    }
    u64 pid_tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&incomplete_modifies, &pid_tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int sys_enter_openat2(struct syscalls_enter_openat2_args *ctx)
{
    u64 flags = 0;
    bpf_probe_read_user(&flags, sizeof(flags), &ctx->how->flags);
    if (is_write_open(flags)) {
        enter_modify(ctx);
        return 0;
    }
    u64 pid_tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&incomplete_modifies, &pid_tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int sys_enter_open_by_handle_at(struct syscalls_enter_open_by_handle_at_args *ctx)
{
    if (is_write_open(ctx->flags)) {
        enter_modify(ctx);
        return 0;
    }
    u64 pid_tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&incomplete_modifies, &pid_tid);
    return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(security_file_open, void *file)
{
    void *path = ptr_to_field(file, CRC_FILE_F_PATH);
    if (path == NULL)
    {
        file_message_t fm = {0};
        push_file_warning(ctx, &fm, FM_MODIFY);
        return 0;
    }
    store_modified_dentry(ctx, path);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int sys_exit_open(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int sys_exit_openat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int sys_exit_openat2(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open_by_handle_at")
int sys_exit_open_by_handle_at(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_creat")
int sys_enter_creat(void *ctx)
{
    // creat is equivalent to calling open with O_CREAT | O_WRONLY | O_TRUNC
    // If we see a creat, we should treat it as a write open
    enter_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int sys_exit_creat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int sys_enter_truncate(void *ctx)
{
    enter_modify(ctx);
    return 0;
}

SEC("kprobe/security_path_truncate")
int BPF_KPROBE(security_path_truncate, const struct path *path)
{
    store_modified_dentry(ctx, (void *)path);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_truncate")
int sys_exit_truncate(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

/* END OPEN-LIKE PROBES */

static __always_inline void _filemod_paths(void *ctx)
{
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL)
        return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL)
        return;

    file_message_t *fm = (file_message_t *)buffer;
    cursor_t cursor = {.buffer = buffer, .offset = &fm->u.action.buffer_len};

    int ret = write_path(ctx, cached_path, &cursor, (tail_call_t){
                                                        .slot = FILE_PATHS,
                                                        .table = &tp_programs,
                                                    });
    if (ret < 0)
        goto EmitWarning;

    // there is a subsequent path we need to also parse; setup
    // cached_path and then tailcall back
    if (cached_path->next_path)
    {
        int filter_tag = cached_path->filter_tag;
        init_filtered_cached_path(cached_path, cached_path->next_path, cached_path->original_vfsmount);
        // avoid further filtering if already succeeded on this path
        if (filter_tag >= 0)
        {
            cached_path->filter_state = -1;
            cached_path->filter_tag = filter_tag;
        }
        write_null_char(buffer, cursor.offset);

        if (fm->type == FM_RENAME) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            rename_name_t *name = bpf_map_lookup_elem(&rename_names, &pid_tgid);
            if (name == NULL) goto NoEvent;
            if (name->pid_tgid != pid_tgid) goto EventMismatch;
            // if there is a rename_name then write that first
            write_segment(ctx, cached_path, &cursor, name->name);
            goto RenameFinished;

        EventMismatch:
            fm->type = FM_WARNING;
            fm->u.warning.pid_tgid = pid_tgid;
            fm->u.warning.message_type.file = FM_RENAME;
            fm->u.warning.code = W_PID_TGID_MISMATCH;
            fm->u.warning.info.stored_pid_tgid = name->pid_tgid;

            push_file_message(ctx, fm);
            goto Done;

        NoEvent:
            // Either the map disappeared or the element aged out so we just ignore it.
            goto Done;

        RenameFinished:;
        }

        bpf_tail_call(ctx, &tp_programs, FILE_PATHS);
        // if the tail call fails - let it fall through; we'll send what we have
    }

    if (cached_path->filter_tag < 0)
        goto Done; // Didn't match watched path filter

    fm->u.action.tag = cached_path->filter_tag;
    push_flexible_file_message(ctx, fm, *cursor.offset);
    goto Done;

EmitWarning:
    push_file_warning(ctx, fm, fm->type);

Done:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}

SEC("tracepoint/filemod_paths")
int filemod_paths(void *ctx)
{
    _filemod_paths(ctx);
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
