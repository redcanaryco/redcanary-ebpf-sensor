#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/dcache.h>
#include "types.h"
#include "offsets.h"
#include "repeat.h"
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

struct bpf_map_def SEC("maps/read_path_skip") read_path_skip = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tail_call_table") tail_call_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 32,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/process_ids") process_ids = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

#define SKIP_PATH                                    \
    if (skipped >= to_skip)                          \
        goto Send;                                   \
    /* Skip to the parent directory */               \
    bpf_probe_read(&ptr, sizeof(ptr), ptr + parent); \
    skipped += 1;                                    \
    if (!ptr)                                        \
        goto Send;

#define SKIP_PATH_N(N) REPEAT_##N(SKIP_PATH;)

#define SEND_PATH                                                           \
    ev->id = id;                                                            \
    ev->done = FALSE;                                                       \
    ev->telemetry_type = TE_PWD;                                            \
    if (br == 0)                                                            \
    {                                                                       \
        bpf_probe_read(&offset, sizeof(offset), ptr + name);                \
        if (!offset)                                                        \
            goto Skip;                                                      \
    }                                                                       \
    __builtin_memset(&ev->u.v.value, 0, VALUE_SIZE);                        \
    count = bpf_probe_read_str(&ev->u.v.value, VALUE_SIZE, (void *)offset); \
    br = ev->u.v.value[0];                                                  \
    if (count >= VALUE_SIZE)                                                \
    {                                                                       \
        br = 1;                                                             \
        ev->u.v.truncated = TRUE;                                           \
        offset = offset + VALUE_SIZE;                                       \
        push_telemetry_event(ctx, ev);                                      \
    }                                                                       \
    else                                                                    \
    {                                                                       \
        if (count > 0)                                                      \
        {                                                                   \
            ev->u.v.truncated = FALSE;                                      \
            push_telemetry_event(ctx, ev);                                  \
        }                                                                   \
        /* we're done here, follow the pointer */                           \
        bpf_probe_read(&ptr, sizeof(ptr), ptr + parent);                    \
        to_skip += 1;                                                       \
        if (!ptr)                                                           \
            goto Skip;                                                      \
        if (br == '/')                                                      \
            goto Skip;                                                      \
        br = 0;                                                             \
    }

#define SEND_PATH_N(N) REPEAT_##N(SEND_PATH;)

#define READ_CHAR_STR                                                   \
    ev.id = id;                                                         \
    ev.done = FALSE;                                                    \
    ev.telemetry_type = TE_CHAR_STR;                                    \
    __builtin_memset(&ev.u.v.value, 0, VALUE_SIZE);                     \
    count = bpf_probe_read_str(&ev.u.v.value, VALUE_SIZE, (void *)str); \
    if (count >= VALUE_SIZE)                                            \
    {                                                                   \
        ev.u.v.truncated = TRUE;                                        \
        str = str + VALUE_SIZE - 1;                                     \
        push_telemetry_event(ctx, &ev);                                 \
    }                                                                   \
    else                                                                \
    {                                                                   \
        if (count > 0)                                                  \
        {                                                               \
            ev.u.v.truncated = FALSE;                                   \
            push_telemetry_event(ctx, &ev);                             \
            goto DONE_READING;                                          \
        }                                                               \
    }

#define READ_CHAR_STR_N(N) REPEAT_##N(READ_CHAR_STR)

static __always_inline void push_telemetry_event(struct pt_regs *ctx, ptelemetry_event_t ev)
{
    bpf_perf_event_output(ctx, &script_events, bpf_get_smp_processor_id(), ev, sizeof(*ev));
    __builtin_memset(ev, 0, sizeof(telemetry_event_t));
}

SEC("kprobe/script_load")
int kprobe__script_load(struct pt_regs *ctx)
{
    struct linux_binprm *bprm = (struct linux_binprm *)PT_REGS_PARM1(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&load_script_map, &index, &bprm, BPF_ANY);

    return 0;
}

SEC("kprobe/handle_pwd")
int kprobe__handle_pwd(struct pt_regs *ctx)
{
    char br = 0;
    int count = 0;
    u32 to_skip = 0;
    u32 skipped = 0;
    telemetry_event_t sev = {0};
    ptelemetry_event_t ev = &sev;
    unsigned long long ret = 0;

    // if the ID already exists, we are tail-calling into ourselves, skip ahead to reading the path
    u64 p_t = bpf_get_current_pid_tgid();
    u64 id = (u64)bpf_map_lookup_elem(&process_ids, &p_t);
    if (id)
    {
        __builtin_memcpy(&id, (void *)id, sizeof(u64));
    }

    // since index will start at zero, we can use it here
    u64 offset = 0;
    void *ptr = (void *)bpf_get_current_task();
    if (read_value(ptr, CRC_TASK_STRUCT_FS, &ptr, sizeof(ptr)) < 0)
        goto Skip;

    offset = CRC_FS_STRUCT_PWD;
    offset = (u64)bpf_map_lookup_elem(&offsets, &offset);
    if (!offset)
    {
        goto Skip;
    }

    ptr = ptr + *(u32 *)offset; // ptr to pwd

    if (read_value(ptr, CRC_PATH_DENTRY, &ptr, sizeof(ptr)) < 0)
    {
        goto Skip;
    }

    SET_OFFSET(CRC_DENTRY_D_NAME);
    u32 qstr_len = *(u32 *)offset; // variable name doesn't match here, we're reusing it to preserve stack

    SET_OFFSET(CRC_QSTR_NAME);
    u32 name = qstr_len + *(u32 *)offset; // offset to name char ptr within qstr of dentry

    SET_OFFSET(CRC_DENTRY_D_PARENT);
    u32 parent = *(u32 *)offset; // offset of d_parent

    u32 *_to_skip = (u32 *)bpf_map_lookup_elem(&read_path_skip, &to_skip);
    if (_to_skip)
    {
        to_skip = *_to_skip;
    }

    if (to_skip != 0)
    {
        SKIP_PATH_N(150);
    }

Send:
    SEND_PATH_N(10);

    // update to_skip, reuse skipped as index by resetting it
    skipped = 0;
    bpf_map_update_elem(&read_path_skip, &skipped, &to_skip, BPF_ANY);
    // tail call back in
    ret = bpf_tail_call(ctx, &tail_call_table, HANDLE_PWD);

Skip:
    skipped = 0;
    bpf_map_delete_elem(&read_path_skip, &skipped);
    bpf_map_delete_elem(&process_ids, &p_t);
    ev->id = id;
    return 0;
}

SEC("kretprobe/ret_script_load")
int kretprobe__ret_script_load(struct pt_regs *ctx)
{
    char br = 0;
    u64 id = 0;
    u32 count = 0;
    void **bprmp = NULL;
    void *str = NULL;
    u64 loaded = CRC_LOADED;
    unsigned char *bprm = NULL;
    u64 p_t = bpf_get_current_pid_tgid();

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
    id = bpf_get_prandom_u32();
    ev.id = id;
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

    bprm = (unsigned char *)*bprmp;
    if (NULL == bprm)
    {
        return 0;
    }

    // Create the initial script event in the cache
    push_telemetry_event(ctx, &ev);

    // Get filename. It may only be the first part
    ret = read_value(bprm, CRC_LINUX_BINPRM_FILENAME, &str, sizeof(str));
    if (ret < 0)
    {
        return 0;
    }
    count = bpf_probe_read_str(&ev.u.v.value, sizeof(ev.u.v.value), str);

    // Increment the pointer the number of bytes read -1 for the null terminator
    str += sizeof(ev.u.v.value) - 1;

    // This is used to check if it's an absolute path (starts with '/')
    br = ev.u.v.value[0];

    // Output the path. It may only be the first part if the path/name is long
    ev.id = id;
    ev.done = 0;
    ev.telemetry_type = TE_CHAR_STR;
    push_telemetry_event(ctx, &ev);

    // If we reached the max we could read and there is still more to read
    if (count >= sizeof(ev.u.v.value))
    {
        // We need to make sure that we read enough times to read PATH_MAX
        // This macro jumps to DONE_READING when it has read to the null byte
        READ_CHAR_STR_N(29)

    DONE_READING:
        // If the first character is '/' then we have an aboslute path and so
        // we can skip getting cwd
        if (br == '/')
        {
            goto Skip;
        }
    }
    // If we read less than value size and the first character is '/' then we
    // have an aboslute path and so we can skip getting cwd
    else if (br == '/')
    {
        goto Skip;
    }

    // If we made it here we need to get the cwd. Add the id we used for our event
    // the map and then call the handle_pwd function
    bpf_map_update_elem(&process_ids, &p_t, &id, BPF_ANY);

    count = 0;
    bpf_map_update_elem(&read_path_skip, &count, &count, BPF_ANY);
    bpf_tail_call(ctx, &tail_call_table, HANDLE_PWD);

Skip:
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
