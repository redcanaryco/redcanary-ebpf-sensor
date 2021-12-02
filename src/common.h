#ifndef _COMMON_H
#define _COMMON_H
#include "bpf_helpers.h"
#include "bpf_tracing.h"

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

#define SET_OFFSET(CRC)                                   \
    offset = CRC;                                         \
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset); \
    if (!offset)                                          \
        goto Skip;

static __always_inline int read_value(void *base, u64 offset, void *dest, size_t dest_size)
{
    /* null check the base pointer first */
    if (!base)
    {
        bpf_printk("Base should not be NULL\n");
        return -1;
    }

    u64 _offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (_offset)
    {
        int ret = bpf_probe_read(dest, dest_size, base + *(u32 *)_offset);
        return ret;
    }

    bpf_printk("Failed to read offset: %lx\n", offset);
    return -1;
}

#endif //_COMMON_H
