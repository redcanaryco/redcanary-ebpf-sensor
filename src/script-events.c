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
    char end = 0;
    u32 count = 0;
    void **bprmp = NULL;
    void *file_ptr = NULL;
    u64 loaded = CRC_LOADED;
    unsigned char *bprm = NULL;

    // Make sure the function succeeded
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

    // Verify that the offsets are loaded
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    if (!loaded)
    {
        return 0;
    }

    // Get the stored pointer to the linux_binprm structure and clear it out of the map
    bprmp = bpf_map_lookup_elem(&load_script_map, &ev.u.script_info.process.pid);
    if (NULL == bprmp)
    {
        return 0;
    }
    bpf_map_delete_elem(&load_script_map, &ev.u.script_info.process.pid);

    // Make sure it isn't NULL
    bprm = (unsigned char *)*bprmp;
    if (NULL == bprm)
    {
        return 0;
    }

    // Get filename
    ret = read_value(bprm, CRC_BPRM_FILENAME, &file_ptr, sizeof(file_ptr));
    if (ret < 0)
    {
        return 0;
    }

    // Read the filename
    bpf_probe_read_str(&ev.u.script_info.path, sizeof(ev.u.script_info.path), file_ptr);

    // Output the path
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    // If the path is / then we don't need to do anything else
    end = ev.u.script_info.path[0];
    if (end == '/')
    {
        return 0;
    }

    u64 offset = 0;
    void *ptr = (void *)bpf_get_current_task();

    // Get the pointer to the fs field in current
    if (read_value(ptr, CRC_TASK_STRUCT_FS, &ptr, sizeof(ptr)) < 0)
    {
        goto Skip;
    }

    // Get the offset for pwd in fs_struct
    SET_OFFSET(CRC_FS_STRUCT_PWD);

    // Read the Dentry pointer for pwd
    ptr = ptr + *(u32 *)offset; // ptr to pwd
    if (read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr)) < 0)
    {
        goto Skip;
    }

    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 qstr_len = *(u32 *)offset;

    SET_OFFSET(CRC_QSTR_NAME);
    u32 name = qstr_len + *(u32 *)offset;

    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset;

#pragma clang loop unroll(full)
    for (int i = 0; i < 64; i++)
    {
        bpf_probe_read(&offset, sizeof(offset), ptr + name);
        if (!offset)
        {
            goto Skip;
        }

        __builtin_memset(&ev.u.script_info.path, 0, sizeof(ev.u.script_info.path));
        count = bpf_probe_read_str(&ev.u.script_info.path, sizeof(ev.u.script_info.path), (void *)offset);
        if (count < 0)
        {
            return 0;
        }

        end = ev.u.script_info.path[0];
        if (end == '/')
        {
            goto Skip;
        }
        bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

        // This gets the next directory up
        bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);
    }

Skip:
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
