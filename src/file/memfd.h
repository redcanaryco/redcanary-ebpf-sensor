#include "maps.h"
#include "modify.h"
#include "push_file_message.h"
#include "vmlinux.h"

#include "common/definitions.h"

static __always_inline void enter_memfd_create(struct syscalls_enter_memfd_create_args *ctx)
{
    incomplete_file_message_t event = {0};

    // syscalls_enter_memfd_create_args is a superset of syscalls_enter_generic_args
    prepare_file_message((struct syscalls_enter_generic_args *)ctx, FM_MEMFD_CREATE, &event);

    event.memfd_create.flags = ctx->flags;
    event.memfd_create.uname = ctx->uname;

    try_insert_incomplete_file_message((struct syscalls_enter_generic_args*)ctx, &event);
}

static __always_inline file_message_t* exit_memfd(struct syscalls_exit_args *ctx, u64 pid_tgid, incomplete_file_message_t* event) {
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return NULL;

    file_message_t *fm = (file_message_t *)buffer;

    fm->type = event->kind;
    fm->u.action.pid = pid_tgid >> 32;
    fm->u.action.mono_ns = event->start_ktime_ns;
    fm->u.action.u.memfd_create.flags = event->memfd_create.flags;
    fm->u.action.u.memfd_create.fdno = ctx->ret;
    fm->u.action.buffer_len = sizeof(file_message_t);

    u64 dynamic_size = sizeof(file_message_t); 

    // if present, write the memfd's name into the string buffer.
    if (event->memfd_create.uname != NULL) {
        // note that the name as read is the name passed by the caller, without
        // the `memfd:` prepended by the kernel.
        char* name_buf = (void*)buffer + dynamic_size;
        long ret = bpf_probe_read_user_str(name_buf, MFD_NAME_MAX_LEN+1, event->memfd_create.uname);
        if (ret < 0) {
            file_message_t fm = {0};
            fm.type = FM_WARNING;
            fm.u.warning.probe_id = ctx->__syscall_nr;
            fm.u.warning.pid_tgid = bpf_get_current_pid_tgid();
            fm.u.warning.message_type.file = FM_MEMFD_CREATE;
            fm.u.warning.code = W_READ_MEMFD_NAME;
            fm.u.warning.info.err = ret;

            push_file_message((struct syscalls_enter_generic_args *)ctx, &fm);

            // this should not be fatal. the name is informative, but has no
            // function. ensure that there isn't an unterminated string in the
            // buffer as the result of the failed read.
            name_buf[0] = (char)0;
        }

        dynamic_size += ret;
    }

    push_flexible_file_message(ctx, fm, dynamic_size);

    // to reuse POP_AND_SETUP this function needs declare a file_message_t* return type
    return NULL;
}