#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include "types.h"
#include "offsets.h"
#include "common.h"

struct bpf_map_def SEC("maps/load_script_map") load_script_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/script_events") script_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = MAX_TELEMETRY_STACK_ENTRIES * 64,
    .pinning = 0,
    .namespace = "",
};

SEC("kprobe/script_load")
int kprobe__script_load(struct pt_regs *ctx)
{
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&load_script_map, &index, &bprm, BPF_ANY);

    return 0;
}

SEC("kretprobe/ret_script_load")
int kretprobe__ret_script_load(struct pt_regs *ctx)
{
    void *file_ptr = NULL;
    u64 offset = 0;

    // Get the return value from inet_csk_accept
    int ret = PT_REGS_RC(ctx);
    if (ret < 0)
    {
        return 0;
    }

    // Just to be safe 0 out the structs
    telemetry_event_t ev;
    __builtin_memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_SCRIPT;
    ev.u.script_info.mono_ns = bpf_ktime_get_ns();

    // Get Process data and set pid and comm string
    ev.u.script_info.process.pid = (u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(ev.u.script_info.process.comm, sizeof(ev.u.script_info.process.comm));

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    if (!loaded)
    {
        return 0;
    }

    void **bprmp = bpf_map_lookup_elem(&load_script_map, &ev.u.script_info.process.pid);
    if (NULL == bprmp)
    {
        bpf_printk("Failed to lookup bprmp\n");
        return 0;
    }
    bpf_map_delete_elem(&load_script_map, &ev.u.script_info.process.pid);

    unsigned char *bprm = (unsigned char *)*bprmp;
    if (NULL == bprm)
    {
        bpf_printk("Failed to deref bprmp\n");
        return 0;
    }

    // Get filepath
    ret = read_value(bprm, CRC_BPRM_FILE, &file_ptr, sizeof(file_ptr));
    if (ret == -1)
    {
        bpf_printk("Failed to read file_ptr\n");
        return 0;
    }

    offset = CRC_FILE_F_PATH;
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (!offset)
    {
        bpf_printk("Failed to read offsets\n");
        return 0;
    }

    void *dentry = NULL;
    bpf_probe_read(&dentry, sizeof(dentry), file_ptr + 8 + *(u32 *)offset);
    if (dentry == NULL)
    {
        bpf_printk("Failed to get the offset thing\n");
    }

    void *parent_dentry = NULL;
    struct qstr d_name;
    __builtin_memset(&d_name, 0, sizeof(d_name));

    read_value(dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
    read_value(dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
    bpf_probe_read(&ev.u.script_info.path, 128, (void *)d_name.name);
    bpf_printk("%s\n", d_name.name);
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++)
    {
        read_value(parent_dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
        read_value(parent_dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
        bpf_probe_read(&ev.u.script_info.path, 128, (void *)d_name.name);
        bpf_printk("%s\n", ev.u.script_info.path);
        if (ev.u.script_info.path[0] == '/')
        {
            goto END;
        }
        bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
        __builtin_memset(&ev.u.script_info.path, 0, sizeof(ev.u.script_info.path));
    }
// read_value(dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
// read_value(dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
// bpf_printk("Dentry name: %s\n", d_name.name);

// read_value(parent_dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
// bpf_printk("Parent dentry name: %s\n", d_name.name);

// bpf_printk("parent_dentry: %llx\n", parent_dentry);
// read_value(parent_dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
// read_value(parent_dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
// bpf_printk("Parent parent dentry name: %s\n", d_name.name);

// bpf_printk("parent_dentry: %llx\n", parent_dentry);
// read_value(parent_dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
// read_value(parent_dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
// bpf_printk("Parent parent parent dentry name: %s\n", d_name.name);

// bpf_printk("parent_dentry: %llx\n", parent_dentry);
// read_value(parent_dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
// read_value(parent_dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
// bpf_printk("Parent parent parent dentry name: %s\n", d_name.name);

// Output data to generator
END:
    ev.done = 1;
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
