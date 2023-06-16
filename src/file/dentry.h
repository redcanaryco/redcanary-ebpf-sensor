#pragma once

#include "../common/types.h"
#include "../common/helpers.h"

// fill file_info and file_owner fields from fields on the passed in dentry pointer
// the file_owner pointer may be null if you do not want to get those values
static __always_inline int extract_file_info_owner(void *dentry, file_info_t *file_info, file_ownership_t *file_owner)
{
    void *d_inode = read_field_ptr(dentry, CRC_DENTRY_D_INODE);
    if (d_inode == NULL) {
        // TODO: Once we are confident we can ignore dentries without inodes, return a "filter me" value
        // Right now we are only aware of this happening with mkdir in cgroupfs
        // Set some invalid values so that we can still resolve the path and see which one it was.
        file_info->inode = 0;
        file_info->devmajor = 0;
        file_info->devminor = 0;
        file_owner->uid = 0;
        file_owner->gid = 0;
        file_owner->mode = 0;
        return 0;
    }

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

    // uid/gid/mode
    if (read_field(d_inode, CRC_INODE_I_UID, &file_owner->uid, sizeof(file_owner->uid)) < 0)
        return -1;
    if (read_field(d_inode, CRC_INODE_I_GID, &file_owner->gid, sizeof(file_owner->gid)) < 0)
        return -1;
    if (read_field(d_inode, CRC_INODE_I_MODE, &file_owner->mode, sizeof(file_owner->mode)) < 0)
        return -1;

    return 0;
}
