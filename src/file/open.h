#include "vmlinux.h"

#include "common/types.h"

struct syscalls_enter_open_args {
    __u64 unused;
    long __syscall_nr;
    const char *filename;
    long flags;
    umode_t mode;
};

struct syscalls_enter_openat_args {
    __u64 unused;
    long __syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    umode_t mode;
};

struct syscalls_enter_openat2_args {
    __u64 unused;
    long __syscall_nr;
    long dfd;
    const char *filename;
    struct open_how *how;
    size_t usize;
};

struct syscalls_enter_open_by_handle_at_args {
    __u64 unused;
    long __syscall_nr;
    long mountdirfd;
    struct file_handle *handle;
    long flags;
};

int is_write_open(long flags) {
  return (flags & (O_CREAT | O_TRUNC | O_RDWR | O_WRONLY | O_APPEND));
}
