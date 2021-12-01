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
    char br = 0;
    u32 count = 0;
    //void *fs = NULL;
    //void *pwd = NULL;
    void **bprmp = NULL;
    void *file_ptr = NULL;
    //struct qstr d_name;
    u64 loaded = CRC_LOADED;
    unsigned char *bprm = NULL;

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

    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    if (!loaded)
    {
        return 0;
    }

    bprmp = bpf_map_lookup_elem(&load_script_map, &ev.u.script_info.process.pid);
    if (NULL == bprmp)
    {
        bpf_printk("Failed to lookup bprmp\n");
        return 0;
    }
    bpf_map_delete_elem(&load_script_map, &ev.u.script_info.process.pid);

    bprm = (unsigned char *)*bprmp;
    if (NULL == bprm)
    {
        bpf_printk("Failed to deref bprmp\n");
        return 0;
    }

    // Get filename
    ret = read_value(bprm, CRC_BPRM_FILENAME, &file_ptr, sizeof(file_ptr));
    if (ret < 0)
    {
        bpf_printk("Failed to read filename_buf\n");
        return 0;
    }

    bpf_probe_read_str(&ev.u.script_info.path, sizeof(ev.u.script_info.path), file_ptr);
    //bpf_printk("Read script info path\n");
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
    br = ev.u.script_info.path[0];
    if (br == '/')
    {
        return 0;
    }

    void *cur = (void *)bpf_get_current_task();
    if (NULL == cur)
    {
        bpf_printk("Failed to get current\n");
        return 0;
    }

    u64 offset = 0;
    void *ptr = (void *)bpf_get_current_task();
    if (read_value(ptr, CRC_TASK_STRUCT_FS, &ptr, sizeof(ptr)) < 0)
        goto Skip;

    offset = CRC_FS_STRUCT_PWD;
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (!offset)
        goto Skip;
    ptr = ptr + *(u32 *)offset; // ptr to pwd

    if (read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr)) < 0)
        goto Skip;

    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 qstr_len = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    SET_OFFSET(CRC_QSTR_NAME);
    u32 name = qstr_len + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset; // offset of d_parent

#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++)
    {
        bpf_probe_read(&offset, sizeof(offset), ptr + name);
        if (!offset)
            goto Skip;
        __builtin_memset(&ev.u.script_info.path, 0, sizeof(ev.u.script_info.path));
        count = bpf_probe_read_str(&ev.u.script_info.path, sizeof(ev.u.script_info.path), (void *)offset);
        if (count < 0)
        {
            bpf_printk("Failed to read string\n");
            return 0;
        }
        bpf_printk("Path: %s\n", ev.u.script_info.path);

        br = ev.u.script_info.path[0];
        if (br == '/')
        {
            goto Skip;
        }
        bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

        // This gets the next directory up
        bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);
    }

    // #pragma clang loop unroll(full)
    //     for (int i = 0; i < 16; i++)
    //     {
    //         read_value(parent_dentry, CRC_DENTRY_D_NAME, &d_name, sizeof(d_name));
    //         read_value(parent_dentry, CRC_DENTRY_D_PARENT, &parent_dentry, sizeof(parent_dentry));
    //         bpf_probe_read(&ev.u.script_info.path, 128, (void *)d_name.name);
    //         bpf_printk("%s\n", ev.u.script_info.path);
    //         if (ev.u.script_info.path[0] == '/')
    //         {
    //             goto Skip;
    //         }
    //         bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
    //         __builtin_memset(&ev.u.script_info.path, 0, sizeof(ev.u.script_info.path));
    //     }

Skip:
    //bpf_printk("Output event\n");
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
