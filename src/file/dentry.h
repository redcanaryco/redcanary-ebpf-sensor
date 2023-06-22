#pragma once

#include "../common/types.h"
#include "../common/helpers.h"

// fill file_owner fields from fields on the passed in inode pointer
static __always_inline int extract_file_owner(void *d_inode, file_ownership_t *file_owner)
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
static __always_inline int extract_file_info_owner(void *d_inode, file_info_t *file_info, file_ownership_t *file_owner)
{
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

    if (file_owner == NULL) return 0;

    return extract_file_owner(d_inode, file_owner);
}
