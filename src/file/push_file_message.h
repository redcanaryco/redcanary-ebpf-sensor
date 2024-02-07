#pragma once

#include "../common/buffer.h"
#include "../common/warning.h"

// The map where file event messages get emitted to
struct bpf_map_def SEC("maps/file_events") file_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

// pushes a message to the file_events perfmap for the current CPU.
static __always_inline int push_file_message(void *ctx, file_message_t *fm)
{
    return bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, fm, sizeof(*fm));
}

// pushes a message with an extra `dynamic_size` number of bytes. It
// will never send more than `MAX_PERCPU_BUFFER` number of bytes. It
// is a *bug* if dynamic_size here is larger than MAX_PERCPU_BUFFER
// and it will cause the number of bytes to to dynamic_size %
// MAX_PERCPU_BUFFER.
static __always_inline int push_flexible_file_message(void *ctx, file_message_t *ev, u64 dynamic_size)
{
    // The -1 and +1 logic is here to prevent a buffer that is exactly
    // MAX_PERCPU_BUFFER size to become 0 due to the bitwise AND. We
    // know that dynamic_size will never be 0 so this is safe.
    u64 size_to_send = ((dynamic_size - 1) & (MAX_PERCPU_BUFFER - 1)) + 1;
    return bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, ev, size_to_send);
}

// pushes a warning to the process_events perfmap for the current CPU.
static __always_inline int push_file_warning(void *ctx, file_message_t *fm,
                                             file_message_type_t fm_type, u64 probe_id)
{
    fm->type = FM_WARNING;
    message_type_t m_type;
    m_type.file = fm_type;
    fm->u.warning.probe_id = probe_id;

    load_warning_info(&fm->u.warning, m_type);

    return push_file_message(ctx, fm);
}
