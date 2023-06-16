// SPDX-License-Identifier: GPL-2.0+

// Configure path.h to include filter code
#define USE_PATH_FILTER 1

#include <asm/ptrace.h>
#include <linux/path.h>

#include "common/bpf_helpers.h"
#include "file/mkdir.h"

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

SEC("kprobe/security_path_mkdir")
int BPF_KPROBE(security_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode) {
    store_dentry(ctx, (void *)dir, (void *)dentry);
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
