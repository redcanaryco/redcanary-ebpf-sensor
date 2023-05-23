#pragma once

// maximum size of each buffer (since they may have flexible arrays at
// the end)
#define MAX_PERCPU_BUFFER (1 << 15) // 32 KB

// used for events with flexible sizes (i.e., exec*) so it can send
// extra data. Used in conjuction with a map such that it does not use
// the stack size limit.
typedef struct
{
    char buf[MAX_PERCPU_BUFFER];
} buf_t;

// a type that points to a buffer and the current write position within
// that buffer
typedef struct
{
    buf_t *buffer;
    u32 *offset;
} cursor_t;

// A per cpu buffer that can hold more data than allowed in the
// stack. Used to collect data of variable length such as a string.
struct bpf_map_def SEC("maps/buffers") buffers = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(buf_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};
