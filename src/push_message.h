#pragma once

// The map where process event messages get emitted to
struct bpf_map_def SEC("maps/process_events") process_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

// pushes a message to the process_events perfmap for the current CPU.
static __always_inline int push_message(struct pt_regs *ctx, pprocess_message_t pm)
{
    return bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, pm, sizeof(*pm));
}
