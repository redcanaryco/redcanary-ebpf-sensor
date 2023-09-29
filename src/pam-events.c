#include "vmlinux.h"

#include "common/common.h"
#include "common/types.h"

struct bpf_map_def SEC("maps/pam_hash") pam_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(pam_event_t),
    .max_entries = 256,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/pam_events") pam_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

#define DECLARE_PAM_EVENT(STAGE)               \
    u64 pid_tgid = bpf_get_current_pid_tgid(); \
    u32 pid = pid_tgid >> 32;                  \
    u32 tid = pid_tgid & 0xFFFFFFFF;           \
    u64 mono_ns = bpf_ktime_get_ns();          \
    pam_event_t ev = {                         \
        .syscall_pattern = SP_USERMODE,        \
        .pid = pid,                            \
        .tid = tid,                            \
        .stage = STAGE,                        \
        .mono_ns = mono_ns,                    \
    }

SEC("uprobe/pam_start")
int uprobe__pam_start(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_START);
    bpf_probe_read(ev.u.pam_start.service_name, sizeof(ev.u.pam_start.user_name), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(ev.u.pam_start.service_name, sizeof(ev.u.pam_start.user_name), (void *)PT_REGS_PARM2(ctx));
    ev.pam_handle = (u64)PT_REGS_PARM4(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_start")
int uretprobe__pam_start(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    if (0 == PT_REGS_RC(ctx))
    {
        bpf_probe_read(&ppam->pam_handle, sizeof(ppam->pam_handle), (void *)ppam->pam_handle);

        bpf_perf_event_output(ctx,
                              &pam_events,
                              BPF_F_CURRENT_CPU,
                              ppam,
                              sizeof(*ppam));
    }

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_end")
int uprobe__pam_end(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_END);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          BPF_F_CURRENT_CPU,
                          &ev,
                          sizeof(ev));
    return 0;
}

SEC("uprobe/pam_authenticate")
int uprobe__pam_authenticate(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_AUTHENTICATE);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.flags = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_authenticate")
int uretprobe__pam_authenticate(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          BPF_F_CURRENT_CPU,
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_chauthtok")
int uprobe__pam_chauthtok(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_CHAUTHTOK);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.flags = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_chauthtok")
int uretprobe__pam_chauthtok(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          BPF_F_CURRENT_CPU,
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_set_item")
int uprobe__pam_set_item(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_SET_ITEM);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.u.pam_set_item.item_type = (pam_item_type_t)PT_REGS_PARM2(ctx);
    bpf_probe_read(ev.u.pam_set_item.data, sizeof(ev.u.pam_set_item.data), (void *)PT_REGS_PARM3(ctx));
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_set_item")
int uretprobe__pam_set_item(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          BPF_F_CURRENT_CPU,
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

SEC("uprobe/pam_setcred")
int uprobe__pam_setcred(struct pt_regs *ctx)
{
    DECLARE_PAM_EVENT(PAM_SET_CRED);
    ev.pam_handle = (u64)PT_REGS_PARM1(ctx);
    ev.flags = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&pam_hash, &pid_tgid, &ev, BPF_ANY);
    return 0;
}

SEC("uretprobe/pam_setcred")
int uretprobe__pam_setcred(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    pam_event_t *ppam = bpf_map_lookup_elem(&pam_hash, &pid_tgid);
    if (NULL == ppam)
    {
        goto Exit;
    }

    ppam->result = (u32)PT_REGS_RC(ctx);
    bpf_perf_event_output(ctx,
                          &pam_events,
                          BPF_F_CURRENT_CPU,
                          ppam,
                          sizeof(*ppam));

    bpf_map_delete_elem(&pam_hash, &pid_tgid);
Exit:
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
