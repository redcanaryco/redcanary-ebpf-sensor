#pragma once

#include "../common/types.h"
#include "../common/helpers.h"

// fill file_owner fields from fields on the passed in inode pointer
static __always_inline int file_owner_from_ino(void *d_inode, file_ownership_t *file_owner)
{
    // uid/gid/mode
    if (read_field(d_inode, CRC_INODE_I_UID, &file_owner->uid, sizeof(file_owner->uid)) < 0)
        return -1;
    if (read_field(d_inode, CRC_INODE_I_GID, &file_owner->gid, sizeof(file_owner->gid)) < 0)
        return -1;
    if (read_field(d_inode, CRC_INODE_I_MODE, &file_owner->mode, sizeof(file_owner->mode)) < 0)
        return -1;

    return 0;
}

// fill file_info and file_owner fields from fields on the passed in inode pointer
// the file_owner pointer may be null if you do not want to get those values
static __always_inline int file_and_owner_from_ino(void *d_inode, file_info_t *file_info, file_ownership_t *file_owner)
{
    int ret = 0;
    if (file_info != NULL) ret = file_info_from_ino(d_inode, file_info);
    if (ret < 0) return ret;

    if (file_owner != NULL) ret = file_owner_from_ino(d_inode, file_owner);
    return ret;
}

// proxy for extract_file_info_owner that zeroes out the file + owner info if there is no inode
static __always_inline int file_from_dentry(void *dentry, file_info_t *file_info, file_ownership_t *file_owner)
{
    void *d_inode = NULL;
    int ret = read_field(dentry, CRC_DENTRY_D_INODE, &d_inode, sizeof(d_inode));
    if (ret < 0) return ret;
    if (d_inode != NULL) {
        ret = file_and_owner_from_ino(d_inode, file_info, file_owner);
        if (ret < 0) return ret;
    } else {
        // if the dentry has no inode it means that it was either
        // deleted or not set.  zero out the file_info and
        // file_ownership to indicate that but submit the event anyway
        // only if it is a filtered path and handle it in userspace
        if (file_info != NULL) __builtin_memset(file_info, 0, sizeof(*file_info));
        if (file_owner != NULL) __builtin_memset(file_owner, 0, sizeof(*file_owner));
    }

    return 0;
}
