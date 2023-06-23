// SPDX-License-Identifier: GPL-2.0+

// Configure path.h to include filter code
#define USE_PATH_FILTER 1
// Configure path.h with maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 25

#include <linux/kconfig.h>
#include <asm/ptrace.h>
#include <linux/path.h>

#include "common/bpf_helpers.h"
#include "common/types.h"
#include "file/create.h"
#include "file/delete.h"
#include "file/modify.h"

struct syscalls_exit_args
{
    __u64 unused;
    long __syscall_nr;
    long ret;
};

/* START CREATE-LIKE PROBES */

// tail-call-only function to finish and send the symlink message
SEC("kprobe/exit_symlink")
int kprobe__exit_symlink(struct pt_regs *ctx)
{
    exit_symlink(ctx);
    return 0;
}

//
// mkdir probes
//

SEC("tracepoint/sys_enter_mkdir")
int tracepoint__syscalls_sys_enter__mkdir(void *ctx)
{
    enter_create(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_mkdirat")
int tracepoint__syscalls_sys_enter__mkdirat(void *ctx)
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

SEC("tracepoint/sys_exit_mkdir")
int tracepoint__syscalls_sys_exit__mkdir(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_NONE);
    return 0;
}

SEC("tracepoint/sys_exit_mkdirat")
int tracepoint__syscalls_sys_exit__mkdirat(struct syscalls_exit_args *ctx)
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
int BPF_KPROBE_SYSCALL(kprobe__sys_symlink)
{
    enter_create(ctx);
    return 0;
}

SEC("kprobe/sys_symlinkat")
int BPF_KPROBE_SYSCALL(kprobe__sys_symlinkat)
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

SEC("tracepoint/sys_enter_link")
int tracepoint__syscalls_sys_enter__link(void *ctx)
{
    enter_create(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_linkat")
int tracepoint__syscalls_sys_enter__linkat(void *ctx)
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

SEC("tracepoint/sys_exit_link")
int tracepoint__syscalls_sys_exit__link(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_HARD);
    return 0;
}

SEC("tracepoint/sys_exit_linkat")
int tracepoint__syscalls_sys_exit__linkat(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_create(ctx, LINK_HARD);
    return 0;
}

/* END CREATE-LIKE PROBES */

/* START DELETE-LIKE PROBES */

SEC("tracepoint/sys_enter_unlink")
int tracepoint__syscalls_sys_enter__unlink(void *ctx)
{
    enter_delete(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_unlink")
int tracepoint__syscalls_sys_exit__unlink(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_delete(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_unlinkat")
int tracepoint__syscalls_sys_enter__unlinkat(void *ctx)
{
    enter_delete(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_unlinkat")
int tracepoint__syscalls_sys_exit__unlinkat(struct syscalls_exit_args *ctx)
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

SEC("tracepoint/sys_enter_rmdir")
int tracepoint__syscalls_sys_enter__rmdir(void *ctx)
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

SEC("tracepoint/sys_exit_rmdir")
int tracepoint__syscalls_sys_exit__rmdir(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_delete(ctx);
    return 0;
}

/* END DELETE-LIKE PROBES */

/* START CHMOD-LIKE */

SEC("tracepoint/sys_enter_chmod")
int tracepoint__syscalls_sys_enter__chmod(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_chmod")
int tracepoint__syscalls_sys_exit__chmod(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_fchmod")
int tracepoint__syscalls_sys_enter__fchmod(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_fchmod")
int tracepoint__syscalls_sys_exit__fchmod(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_fchmodat")
int tracepoint__syscalls_sys_enter__fchmodat(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_fchmodat")
int tracepoint__syscalls_sys_exit__fchmodat(struct syscalls_exit_args *ctx)
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

SEC("tracepoint/sys_enter_chown")
int tracepoint__syscalls_sys_enter__chown(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_chown")
int tracepoint__syscalls_sys_exit__chown(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_lchown")
int tracepoint__syscalls_sys_enter__lchown(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_lchown")
int tracepoint__syscalls_sys_exit__lchown(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_fchown")
int tracepoint__syscalls_sys_enter__fchown(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_fchown")
int tracepoint__syscalls_sys_exit__fchown(struct syscalls_exit_args *ctx)
{
    if (ctx->ret < 0)
        return 0;
    exit_modify(ctx);
    return 0;
}

SEC("tracepoint/sys_enter_fchownat")
int tracepoint__syscalls_sys_enter__fchownat(void *ctx)
{
    enter_open(ctx);
    return 0;
}

SEC("tracepoint/sys_exit_fchownat")
int tracepoint__syscalls_sys_exit__fchownat(struct syscalls_exit_args *ctx)
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

static __always_inline void filemod_paths(void *ctx)
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
        init_filtered_cached_path(cached_path, cached_path->next_path, cached_path->vfsmount);
        // avoid further filtering if already succeeded on this path
        if (filter_tag >= 0)
        {
            cached_path->filter_state = -1;
            cached_path->filter_tag = filter_tag;
        }
        write_null_char(buffer, cursor.offset);
        bpf_tail_call(ctx, &tp_programs, FILE_PATHS);
        // if the tail call fails - let it fall through; we'll send what we have
    }

    if (cached_path->filter_tag < 0)
        goto NoEvent; // Didn't match watched path filter

    fm->u.action.tag = cached_path->filter_tag;
    push_flexible_file_message(ctx, fm, *cursor.offset);
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;

EmitWarning:
    push_file_warning(ctx, fm, fm->type);

NoEvent:
    // lookup tail calls completed; ensure we re-init cached_path next call
    cached_path->next_dentry = NULL;
    return;
}

SEC("tracepoint/filemod_paths")
int tracepoint__filemod_paths(void *ctx)
{
    filemod_paths(ctx);
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
