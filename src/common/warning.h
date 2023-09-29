#pragma once

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "definitions.h"
#include "types.h"

typedef struct
{
    warning_t code;
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

// Load warning info from the perfmap of the current CPU into the warning variant of some
// message type
static __always_inline void load_warning_info(warning_info_t *wi, message_type_t m_type)
{
    u32 key = 0;
    local_warning_t *warning = (local_warning_t *)bpf_map_lookup_elem(&percpu_warning, &key);
    if (warning != NULL) {
        wi->code = warning->code;
        wi->info = warning->info;
        // reset it so we don't accidentally re-use the same code/info in a new warning
        *warning = (local_warning_t){0};
    }

    wi->pid_tgid = bpf_get_current_pid_tgid();
    wi->message_type = m_type;
}

static __always_inline int set_empty_local_warning(warning_t code)
{
    local_warning_t warning = {0};
    warning.code = code;
    u32 key = 0;
    return bpf_map_update_elem(&percpu_warning, &key, &warning, BPF_ANY);
}

static __always_inline int set_local_warning(warning_t code, error_info_t info)
{
    local_warning_t warning = {0};
    warning.code = code;
    warning.info = info;
    u32 key = 0;
    return bpf_map_update_elem(&percpu_warning, &key, &warning, BPF_ANY);
}
