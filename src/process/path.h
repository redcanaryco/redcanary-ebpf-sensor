#pragma once

// TODO: make programs for newer kernels where we can use higher values

// maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 32

typedef struct
{
    // the dentry to the next path segment
    void *next_dentry;
    // the virtual fs mount where the path is mounted
    void *vfsmount;
} cached_path_t;

// A per cpu cache of dentry so we can hold it across tail calls.
struct bpf_map_def SEC("maps/percpu_path") percpu_path = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(cached_path_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void init_cached_path(cached_path_t *cached_path, void *path)
{
    // cached_path->next_dentry = path->dentry;
    cached_path->next_dentry = read_field_ptr(path, CRC_PATH_DENTRY);

    // cached_path->vfsmount = path->mnt;
    cached_path->vfsmount = read_field_ptr(path, CRC_PATH_MNT);
}

// writes '\0' into the buffer; checks and updates the offset
static __always_inline void write_null_char(buf_t *buffer, u32 *offset)
{
    // We are already full and we do not want the bitwise AND to
    // modulus back onto 0 and overwrite the first bit so just
    // bail. Best case this is the last NULL to write so we are done
    // anyway, worst case there are more strings to write and it will
    // trigger a buffer full warning later.
    if (*offset == MAX_PERCPU_BUFFER) return;

    // `&` safe because we've checked that offset isn't going to
    // "overflow".
    buffer->buf[*offset & (MAX_PERCPU_BUFFER - 1)] = '\0';
    *offset = *offset + 1;
}

// writes the string into the provided buffer. On a
// succesful write it modifies the offset with the length of the read
// string. It deliberately does not handle truncations; it just reads
// up to `max_string`.
static __always_inline int write_string(const char *string, buf_t *buffer, u32 *offset, const u32 max_string)
{
    // A smarter implementation of this wouldn't use max_string but
    // instead would just check MAX_PERCPU_BUFFER - *offset as the max
    // that it can write. However, the verifier seems allergic to an
    // smarter implementation as it complains about potential out of
    // bounds or negative values. While perhaps theoretically possible
    // to improve this with just the right incantations (and maybe
    // turning off some compiler optimizaitons that remove some
    // checks) at this time this is considered good enough (TM).

    // already too full
    if (*offset > MAX_PERCPU_BUFFER - max_string)
        return -PMW_BUFFER_FULL;

    int sz = bpf_probe_read_str(&buffer->buf[*offset], max_string, string);
    if (sz < 0)
    {
        return -PMW_UNEXPECTED;
    }
    else
    {
        *offset = *offset + sz;
        return sz;
    }
}

// writes a d_path into a buffer - tail calling if necessary
static __always_inline int write_path(struct pt_regs *ctx, cached_path_t *cached_path, buf_t *buffer,
                                      tail_call_slot_t tail_call)
{
    u32 *offset = get_offset(CRC_DENTRY_D_NAME);
    if (offset == NULL) return -1;
    u32 name = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    offset = get_offset(CRC_QSTR_NAME);
    if (offset == NULL) return -1;
    name = name + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    offset = get_offset(CRC_DENTRY_D_PARENT);
    if (offset == NULL) return -1;
    u32 dentry_parent = *(u32 *)offset; // offset of d_parent

    offset = get_offset(CRC_MOUNT_MNTPARENT);
    if (offset == NULL) return -1;
    u32 mnt_parent_offset = *(u32 *)offset; // offset of mount->mnt_parent

    offset = get_offset(CRC_VFSMOUNT_MNTROOT);
    if (offset == NULL) return -1;
    u32 mnt_root_offset = *(u32 *)offset; // offset of vfsmount->mnt_root

    offset = get_offset(CRC_MOUNT_MOUNTPOINT);
    if (offset == NULL) return -1;
    u32 mountpoint_offset = *(u32 *)offset; // offset of mount->mountpoint

    offset = get_offset(CRC_MOUNT_MNT);
    if (offset == NULL) return -1;
    u32 mnt_offset = *(u32 *)offset; // offset of mount->mnt

    void *mnt = cached_path->vfsmount - mnt_offset;
    void *mnt_parent = NULL;
    void *mnt_root = NULL;

    bpf_probe_read(&mnt_parent, sizeof(mnt_parent), mnt + mnt_parent_offset);
    bpf_probe_read(&mnt_root, sizeof(mnt_root), cached_path->vfsmount + mnt_root_offset);

    int ret = 0;

// Anything we add to this for-loop will be repeated
// MAX_PATH_SEGMENTS_NOTAIL so be very careful of going over the max
// instruction limit (4096).
#pragma unroll MAX_PATH_SEGMENTS_NOTAIL
    for (int i = 0; i < MAX_PATH_SEGMENTS_NOTAIL; i++)
    {
        if (cached_path->next_dentry == mnt_root)
        {
            if (mnt == mnt_parent) goto AtGlobalRoot;

            // we are done with the path but not with its mount
            // start appending the path to the mountpoint
            bpf_probe_read(&cached_path->next_dentry, sizeof(cached_path->next_dentry), mnt + mountpoint_offset);

            // allow for nested mounts
            mnt = mnt_parent;
            bpf_probe_read(&mnt_parent, sizeof(mnt_parent), mnt + mnt_parent_offset);

            // set what our new mount root is
            cached_path->vfsmount = mnt + mnt_offset;
            bpf_probe_read(&mnt_root, sizeof(mnt_root), cached_path->vfsmount + mnt_root_offset);

            // force a continue early to check if the new path is also at at its root
            continue;
        }

        void *dentry = cached_path->next_dentry;
        bpf_probe_read(&cached_path->next_dentry, sizeof(cached_path->next_dentry), cached_path->next_dentry + dentry_parent);

        if (dentry == cached_path->next_dentry) goto AtGlobalRoot;

        if (bpf_probe_read(&offset, sizeof(offset), dentry + name) < 0)
            goto NameError;

        // NAME_MAX doesn't include null character; so +1 to take it
        // into account. Not all systems enforce NAME_MAX so
        // truncation may happen per path segment. TODO: emit
        // truncation metrics to see if we need to care about this.
        process_message_t *pm = (process_message_t *)buffer;
        ret = write_string((char *)offset, buffer, &pm->u.syscall_info.data.exec_info.buffer_length, NAME_MAX + 1);
        if (ret < 0) goto WriteError;
    }

    bpf_tail_call(ctx, &tail_call_table, tail_call);

    error_info_t info = {0};
    info.tailcall = tail_call;
    set_local_warning(PMW_TAIL_CALL_MAX, info);

    return -1;

 AtGlobalRoot:;
    // let's not forget to write the global root (might be a / or the memfd name)
    if (bpf_probe_read(&offset, sizeof(offset), cached_path->next_dentry + name) < 0)
            goto NameError;

    process_message_t *pm = (process_message_t *)buffer;
    ret = write_string((char *)offset, buffer, &pm->u.syscall_info.data.exec_info.buffer_length, NAME_MAX + 1);
    if (ret < 0) goto WriteError;

    return 0;

 WriteError:;
    error_info_t empty_info = {0};
    if (ret == -PMW_UNEXPECTED) {
        set_local_warning(PMW_READ_PATH_STRING, empty_info);
    } else {
        set_local_warning(-ret, empty_info);
    }

    return -1;

 NameError:;
    error_info_t read_error_info = {0};
    read_error_info.offset_crc = CRC_QSTR_NAME;
    set_local_warning(PMW_PTR_FIELD_READ, read_error_info);

    return -1;
}
