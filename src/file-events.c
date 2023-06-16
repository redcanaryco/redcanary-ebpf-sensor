// SPDX-License-Identifier: GPL-2.0+

// Configure path.h to include filter code
#define USE_PATH_FILTER 1
// Configure path.h with maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 12

#include <asm/ptrace.h>
#include <linux/path.h>

#include "common/bpf_helpers.h"
#include "file/create.h"

// tail-call-only function to finish and send the create message
// Stored in index EXIT_CREATE
SEC("kprobe/exit_create")
int kprobe__exit_create(struct pt_regs *ctx) {
    exit_create(ctx);
    return 0;
}

//
// mkdir probes
//

SEC("kprobe/sys_mkdir")
int BPF_KPROBE_SYSCALL(kprobe__sys_mkdir) {
    enter_create(ctx, LINK_NONE);
    return 0;
}

SEC("kprobe/sys_mkdirat")
int BPF_KPROBE_SYSCALL(kprobe__sys_mkdirat) {
    enter_create(ctx, LINK_NONE);
    return 0;
}

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(security_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode) {
    store_dentry(ctx, (void *)dir, (void *)dentry, NULL);
    return 0;
}

SEC("kretprobe/ret_do_mkdirat")
int BPF_KRETPROBE(do_mkdirat, int retval) {
    if (retval < 0) return 0;
    bpf_tail_call(ctx, &tail_call_table, EXIT_CREATE);
    return 0;
}

//
// symlink probes
//

SEC("kprobe/sys_symlink")
int BPF_KPROBE_SYSCALL(kprobe__sys_symlink) {
    enter_create(ctx, LINK_SYMBOLIC);
    return 0;
}

SEC("kprobe/sys_symlinkat")
int BPF_KPROBE_SYSCALL(kprobe__sys_symlinkat) {
    enter_create(ctx, LINK_SYMBOLIC);
    return 0;
}

SEC("kprobe/security_path_symlink")
int BPF_KPROBE(security_path_symlink, const struct path *dir, struct dentry *dentry, const char *old_name) {
    store_dentry(ctx, (void *)dir, (void *)dentry, (void *)old_name);
    return 0;
}

SEC("kretprobe/ret_vfs_symlink")
int BPF_KRETPROBE(ret_vfs_symlink, int retval) {
    if (retval < 0) return 0;
    bpf_tail_call(ctx, &tail_call_table, EXIT_CREATE);
    return 0;
}

//
// hard link probes
//

SEC("kprobe/sys_link")
int BPF_KPROBE_SYSCALL(kprobe__sys_link) {
    enter_create(ctx, LINK_HARD);
    return 0;
}

SEC("kprobe/sys_linkat")
int BPF_KPROBE_SYSCALL(kprobe__sys_linkat) {
    enter_create(ctx, LINK_HARD);
    return 0;
}

SEC("kprobe/security_path_link")
int BPF_KPROBE(security_path_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags) {
    store_dentry(ctx, (void *)new_dir, (void *)new_dentry, (void *)old_dentry);
    return 0;
}

SEC("kretprobe/ret_vfs_link")
int BPF_KRETPROBE(ret_vfs_link, int retval) {
    if (retval < 0) return 0;
    bpf_tail_call(ctx, &tail_call_table, EXIT_CREATE);
    return 0;
}



char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
