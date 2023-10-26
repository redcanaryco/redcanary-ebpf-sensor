#pragma once

#include "../common/common.h"
#include "push_message.h"

static __always_inline void push_exit(void *ctx, pprocess_message_t pm,
                                      process_message_type_t pm_type, u32 pid)
{
    void *ts = (void *)bpf_get_current_task();
    int ret = fill_syscall(&pm->u.syscall_info, ts, pid);
    if (ret > 0) return;
    if (ret < 0) {
        push_warning(ctx, pm, pm_type);
        return;
    }

    pm->type = pm_type;
    push_message(ctx, pm);
}
