#pragma once

#include "push_message.h"
#include "warning.h"

/// Returns the offset to a field. If not found the current CPU's
/// warning_info is set and NULL is returned
static __always_inline u32* get_offset(u64 field) {
    u32 *offset = (u32 *)bpf_map_lookup_elem(&offsets, &field);
    if (offset == NULL) {
        error_info_t info = {0};
        info.offset_crc = field;
        set_local_warning(PMW_READING_FIELD, info);
    }

    return offset;
}

/// Equivalent to &(base->field). If not found the current CPU's
/// warning_info is set and NULL is returned
static __always_inline void* ptr_to_field(void *base, u64 field) {
    u32 *offset = get_offset(field);
    if (offset == NULL) return NULL;

    return base + *offset;
}

/// Equivalent to *dst = base->field. Returns 0 on success, or
/// negative and sets the current CPU's warning_info in case of
/// failure.
static __always_inline int read_field(void *base, u64 field, void *dst, size_t size) {
    void *ptr_to_ptr = ptr_to_field(base, field);
    if (ptr_to_ptr == NULL) return -1;

    int ret = bpf_probe_read(dst, size, ptr_to_ptr);
    if (ret < 0) {
        error_info_t info = {0};
        info.offset_crc = field;
        set_local_warning(PMW_PTR_FIELD_READ, info);
    }

    return ret;
}

/// Equivalent to void base->field. If not found or the pointer is
/// NULL the current CPU's warning_info is set and NULL is returned
static __always_inline void* read_field_ptr(void *base, u64 field) {
    void *dst = NULL;
    if (read_field(base, field, &dst, sizeof(dst)) < 0) return NULL;

    if (dst == NULL) {
        error_info_t info = {0};
        info.offset_crc = field;
        set_local_warning(PMW_NULL_FIELD, info);
    }

    return dst;
}

// accepts a pointer to a `task_struct`. Returns 0 if it is not
// user_process; 1 if it is, and -1 if an error occured.
static __always_inline int is_user_process(void *ts)
{
    void *mmptr = NULL;
    if (read_field(ts, CRC_TASK_STRUCT_MM, &mmptr, sizeof(mmptr)) < 0) {
        return -1;
    }
    return mmptr != NULL;
}

// fills the syscall_info with all the common values. Returns 1 if the
// task struct is not a user process or if the offsets have not yet
// been loaded.
static __always_inline int fill_syscall(syscall_info_t *syscall_info, void *ts, u32 pid)
{
    if (!offset_loaded())
        return 1;
    int ret = is_user_process(ts);
    if (ret < 0) return ret; // error checking if user process
    if (ret == 0) return 1;  // not a user process

    void *real_parent = read_field_ptr(ts, CRC_TASK_STRUCT_REAL_PARENT);
    if (real_parent == NULL) return -1;

    u32 ppid = -1;
    if (read_field(real_parent, CRC_TASK_STRUCT_TGID, &ppid, sizeof(ppid)) < 0) return -1;

    // luid could either be in ts->loginuid OR ts->audit->luid. In
    // most systems it will be in ts->loginuid so let's try that
    // first.
    u32 luid = -1;
    u64 offset_key = CRC_TASK_STRUCT_LOGINUID;
    u32 *offset = (u32 *)bpf_map_lookup_elem(&offsets, &offset_key);
    if (offset == NULL) {
        // if any part of ts->audit->loginuid fails emit a warning as
        // we expect it there when ts->loginuid is not.
        void *audit = read_field_ptr(ts, CRC_TASK_STRUCT_AUDIT);
        if (audit == NULL) return -1;
        if (read_field(audit, CRC_AUDIT_TASK_INFO_LOGINUID, &luid, sizeof(luid)) < 0) return -1;
    } else {
        if (bpf_probe_read(&luid, sizeof(luid), ts + *offset) < 0) {
            error_info_t info = {0};
            info.offset_crc = offset_key;
            set_local_warning(PMW_PTR_FIELD_READ, info);

            return -1;
        }
    }

    u64 uid_gid = bpf_get_current_uid_gid();

    syscall_info->pid = pid;
    syscall_info->ppid = ppid;
    syscall_info->luid = luid;
    syscall_info->euid = uid_gid >> 32;
    syscall_info->egid = uid_gid & 0xFFFFFFFF;
    syscall_info->mono_ns = bpf_ktime_get_ns();

    return 0;
}

// it's argument should be a pointer to a file
static __always_inline int extract_file_info(void *ptr, file_info_t *file_info)
{
    void *f_inode = read_field_ptr(ptr, CRC_FILE_F_INODE);
    if (f_inode == NULL) return -1;

    void *i_sb = read_field_ptr(f_inode, CRC_INODE_I_SB);
    if (i_sb == NULL) return -1;

    // inode
    if (read_field(f_inode, CRC_INODE_I_INO, &file_info->inode, sizeof(file_info->inode)) < 0)
        return -1;

    // device major/minor
    u32 i_dev = 0;
    if (read_field(i_sb, CRC_SBLOCK_S_DEV, &i_dev, sizeof(i_dev)) < 0) return -1;

    file_info->devmajor = MAJOR(i_dev);
    file_info->devminor = MINOR(i_dev);

    return 0;
}
