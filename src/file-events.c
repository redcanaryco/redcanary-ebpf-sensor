// SPDX-License-Identifier: GPL-2.0+

// Configure path.h to include filter code
#define USE_PATH_FILTER 1

#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/fs.h>

#include "common/bpf_helpers.h"
#include "common/types.h"
#include "common/offsets.h"
#include "common/common.h"
#include "common/helpers.h"
#include "common/buffer.h"
#include "common/path.h"
#include "common/warning.h"

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
