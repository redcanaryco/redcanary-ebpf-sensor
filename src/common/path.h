#pragma once

#include "bpf_helpers.h"
#include "buffer.h"
#include "common.h"
#include "offsets.h"
#include "helpers.h"

// TODO: make programs for newer kernels where we can use higher values

#ifndef MAX_PATH_SEGMENTS_NOTAIL
// maximum segments we can read from a d_path before doing a tail call
#define MAX_PATH_SEGMENTS_NOTAIL 25
#endif

#ifndef USE_PATH_FILTER
#define USE_PATH_FILTER 0
#endif

typedef struct
{
    // the dentry to the next path segment
    void *next_dentry;
    // the virtual fs mount where the path is mounted
    void *vfsmount;
#if USE_PATH_FILTER
    // filter state machine state; init to 0 for filtering, -1 for none
    int filter_state;
    // filter match tag; filled by filter when a match is found
    int filter_tag;
    // the next path to process after next_dentry has been *fully* resolved
    void *next_path;
    // a cache of the vfsmount before any of the changes done by `write_path`
    void *original_vfsmount;
#endif
} cached_path_t;

#if USE_PATH_FILTER
// A table containing state transitions for a path parsing filter
struct bpf_map_def SEC("maps/filter_transitions") filter_transitions = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(filter_key_t),
    .value_size = sizeof(filter_value_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};
#endif

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
#if USE_PATH_FILTER
    // no filtering by default
    cached_path->filter_state = -1;
#endif
}

#if USE_PATH_FILTER
static __always_inline void init_filtered_cached_path(cached_path_t *cached_path, void *dentry, void *vfsmount)
{
    cached_path->next_dentry = dentry;
    cached_path->vfsmount = vfsmount;
    // set the filter machine at the start state;
    cached_path->filter_state = 0;
    // clear the filter tag
    cached_path->filter_tag = -1;
    cached_path->next_path = NULL;
    cached_path->original_vfsmount = vfsmount;
}
#endif

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
        return -W_BUFFER_FULL;

    int sz = bpf_probe_read_str(&buffer->buf[*offset], max_string, string);
    if (sz < 0)
    {
        return -W_UNEXPECTED;
    }
    else
    {
        *offset = *offset + sz;
        return sz;
    }
}

// Writes the single path segment (name) into the buffer. Potentially
// updating any filter state if `USE_PATH_FILTER` is defined
static __always_inline int write_segment(void *ctx, cached_path_t *cached_path, cursor_t *buf, void *name) {
#if USE_PATH_FILTER
    // Path filtering, only if the filter is active
    if (cached_path->filter_state >= 0) {
        filter_key_t key = {0};           // the main key storage for filter transition lookups
        filter_value_t *val = NULL;
        key.current_state = cached_path->filter_state;
        if (bpf_probe_read_str(&key.path_segment, MAX_PATH_SEG, name) > 0) {
            val = (filter_value_t *)bpf_map_lookup_elem(&filter_transitions, &key);
        }
        // One retry with "*" path element if not found
        if (val == NULL) {
            filter_key_t retry_key = {0};     // a separate key for retries, to cut down on strcopy
            retry_key.path_segment[0] = '*';
            // The retry_key always uses the same path segment string so we don't need to reset
            retry_key.current_state = cached_path->filter_state;
            val = (filter_value_t *)bpf_map_lookup_elem(&filter_transitions, &retry_key);
        }
        // Terminate the filter lookup if there was no value at either key
        cached_path->filter_state = val ? val->next_state : -1;
    }
#endif

    // NAME_MAX doesn't include null character; so +1 to take it
    // into account. Not all systems enforce NAME_MAX so
    // truncation may happen per path segment. TODO: emit
    // truncation metrics to see if we need to care about this.
    int ret = write_string((char *)name, buf->buffer, buf->offset, NAME_MAX + 1);
    if (ret < 0) goto WriteError;
    return 0;

 WriteError:
    if (ret == -W_UNEXPECTED) {
        set_empty_local_warning(W_READ_PATH_STRING);
    } else {
        set_empty_local_warning(-ret);
    }

    return -1;
}

// writes a d_path into a buffer - tail calling if necessary
// cached_path needs to be initialized with the dentry + vfsmount of the path to resolve
// to use path filtering, set cached_path->filter_state to 0 before calling
// success is indicated by a non-negative return value representing the length of the path
// a filter match is indicated by a positive cached_path->filter_state upon successful return
static __always_inline int write_path(void *ctx, cached_path_t *cached_path, cursor_t *buf,
                                      tail_call_t tail_call)
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
#if USE_PATH_FILTER
    filter_key_t key = {0};           // the main key storage for filter transition lookups
    filter_value_t *val = NULL;

    // We trade some stack space for reduced instructions per loop in the filter logic
    // Because hash maps don't understand null-terminated strings, we have to always
    // zero-out the full path_segment buffer before copying a string into it.
    filter_key_t retry_key = {0};     // a separate key for retries, to cut down on strcopy
    filter_key_t blank_key = {0};     // we copy this blank key over key to zero it easily

    // Init the retry_key's path string, which is always the same
    retry_key.path_segment[0] = '*';
#endif

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

#if USE_PATH_FILTER
        // Path filtering, only if the filter is active
        if (cached_path->filter_state >= 0) {
            val = NULL;
            // We need to reset at least the whole string storage array each time we use the key
            bpf_probe_read(&key, sizeof(filter_key_t), &blank_key);
            key.current_state = cached_path->filter_state;
            if (bpf_probe_read_str(&key.path_segment, MAX_PATH_SEG, offset) > 0) {
                val = (filter_value_t *)bpf_map_lookup_elem(&filter_transitions, &key);
            }
            // One retry with "*" path element if not found
            if (val == NULL) {
                // The retry_key always uses the same path segment string so we don't need to reset
                retry_key.current_state = cached_path->filter_state;
                val = (filter_value_t *)bpf_map_lookup_elem(&filter_transitions, &retry_key);
            }
            // Terminate the filter lookup if there was no value at either key
            cached_path->filter_state = val ? val->next_state : -1;
        }
#endif

        // NAME_MAX doesn't include null character; so +1 to take it
        // into account. Not all systems enforce NAME_MAX so
        // truncation may happen per path segment. TODO: emit
        // truncation metrics to see if we need to care about this.
        ret = write_string((char *)offset, buf->buffer, buf->offset, NAME_MAX + 1);
        if (ret < 0) goto WriteError;
    }

    bpf_tail_call(ctx, tail_call.table, tail_call.slot);

    error_info_t info = {0};
    info.tailcall = tail_call.slot;
    set_local_warning(W_TAIL_CALL_MAX, info);

    return -1;

 AtGlobalRoot:;
    // let's not forget to write the global root (might be a / or the memfd name)
    if (bpf_probe_read(&offset, sizeof(offset), cached_path->next_dentry + name) < 0)
            goto NameError;

#if USE_PATH_FILTER
    // If the filter is still active, it must match on the first try to succeed
    if (cached_path->filter_state >= 0) {
        val = NULL;
        // We need to reset at least the string array of the key
        bpf_probe_read(&key, sizeof(filter_key_t), &blank_key);
        key.current_state = cached_path->filter_state;
        if (bpf_probe_read_str(&key.path_segment, MAX_PATH_SEG, offset) > 0) {
            val = (filter_value_t *)bpf_map_lookup_elem(&filter_transitions, &key);
        }
        // A successful lookup here is only a match if the tag is not an empty string
        if (val && val->tag >= 0) {
            cached_path->filter_state = val->next_state;
            cached_path->filter_tag = val->tag;
        } else {
            cached_path->filter_state = -1;
        }
    }
#endif

    ret = write_string((char *)offset, buf->buffer, buf->offset, NAME_MAX + 1);
    if (ret < 0) goto WriteError;

    return 0;

 WriteError:;
    if (ret == -W_UNEXPECTED) {
        set_empty_local_warning(W_READ_PATH_STRING);
    } else {
        set_empty_local_warning(-ret);
    }

    return -1;

 NameError:;
    error_info_t read_error_info = {0};
    read_error_info.offset_crc = CRC_QSTR_NAME;
    set_local_warning(W_PTR_FIELD_READ, read_error_info);

    return -1;
}
