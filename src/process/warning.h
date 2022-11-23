#pragma once

#include "push_message.h"

typedef struct
{
    process_message_warning_t code;
    error_info_t info;
} local_warning_t;

// A "cpu local" warning so we can easily get/set the current warning
// at any point
struct bpf_map_def SEC("maps/warning") percpu_warning = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(local_warning_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

// pushes a warning to the process_events perfmap for the current CPU.
static __always_inline int push_warning(struct pt_regs *ctx, pprocess_message_t pm,
                                        process_message_type_t pm_type)
{
    pm->type = PM_WARNING;

    u32 key = 0;
    local_warning_t *warning = (local_warning_t *)bpf_map_lookup_elem(&percpu_warning, &key);
    if (warning != NULL) {
        pm->u.warning_info.code = warning->code;
        pm->u.warning_info.info = warning->info;
        // reset it so we don't accidentally re-use the same code/info in a new warning
        *warning = (local_warning_t){0};
    }

    pm->u.warning_info.pid_tgid = bpf_get_current_pid_tgid();
    pm->u.warning_info.message_type = pm_type;

    return push_message(ctx, pm);
}

static __always_inline int set_empty_local_warning(process_message_warning_t code)
{
    local_warning_t warning = {0};
    warning.code = code;
    u32 key = 0;
    return bpf_map_update_elem(&percpu_warning, &key, &warning, BPF_ANY);
}

static __always_inline int set_local_warning(process_message_warning_t code, error_info_t info)
{
    local_warning_t warning = {0};
    warning.code = code;
    warning.info = info;
    u32 key = 0;
    return bpf_map_update_elem(&percpu_warning, &key, &warning, BPF_ANY);
}
