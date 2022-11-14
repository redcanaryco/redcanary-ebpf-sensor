#pragma once

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "offsets.h"

struct bpf_map_def SEC("maps/offsets") offsets = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u32),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

#define DECLARE_EVENT(TYPE, SP)                \
    u64 pid_tgid = bpf_get_current_pid_tgid(); \
    u32 pid = pid_tgid >> 32;                  \
    u32 tid = pid_tgid & 0xFFFFFFFF;           \
    u64 mono_ns = bpf_ktime_get_ns();          \
    TYPE ev = {                                \
        .syscall_pattern = SP,                 \
        .pid = pid,                            \
        .tid = tid,                            \
        .mono_ns = mono_ns,                    \
    }

// This macro assumes you have a label named Skip to jump to
#define SET_OFFSET(CRC)                                   \
    offset_key = CRC;                                     \
    offset = bpf_map_lookup_elem(&offsets, &offset_key);  \
    if (!offset)                                          \
        goto Skip;

static __always_inline void* offset_ptr(void *base, u64 offset_key)
{
    u32 *offset = (u32 *)bpf_map_lookup_elem(&offsets, &offset_key);
    if (!offset)
    {
        return NULL;
    }

    return base + *offset;
}

static __always_inline int read_value(void *base, u64 offset, void *dest, size_t dest_size)
{
    /* null check the base pointer first */
    if (!base)
    {
        return -1;
    }

    u64 _offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (_offset)
    {
        return bpf_probe_read(dest, dest_size, base + *(u32 *)_offset);
    }

    return -1;
}

#define load_event(map, key, ty)                            \
    void *__eventp = bpf_map_lookup_elem(&map, &key);       \
    if (__eventp == NULL) goto NoEvent;                     \
    ty event = {0};                                         \
    __builtin_memcpy(&event, (void *)__eventp, sizeof(ty)); \
    if (event.pid_tgid != key) goto EventMismatch;

// returns NULL if offsets have not yet been loaded
static __always_inline void *offset_loaded()
{
    u64 offset = CRC_LOADED;
    return bpf_map_lookup_elem(&offsets, &offset);
}
