#pragma once

#include "bpf_tracing.h"
#include "buffer.h"
#include "helpers.h"
#include "path.h"
#include "push_message.h"
#include "script.h"

static __always_inline void exit_exec(struct pt_regs *ctx, process_message_type_t pm_type,
                                      tail_call_slot_t tail_call)
{
    /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */
    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    process_message_t *pm = (process_message_t *)buffer;
    int ret = 0;

    // We have been tail-called to find the exename, so go straight to
    // ExeName
    if (cached_path->next_dentry != NULL) goto ExeName;

    /* SANITY CHECKS THAT THE EVENT IS RELEVANT */

    // do not emit failed execs
    int retcode = (int)PT_REGS_RC(ctx);
    if (retcode < 0) return;

    push_scripts(ctx, buffer);

    void *ts = (void *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // do not emit if we couldn't fill the syscall info
    ret = fill_syscall(&pm->u.syscall_info, ts, pid_tgid >> 32);
    if (ret > 0) return;
    if (ret < 0) goto EmitWarning;

    void *mmptr = read_field_ptr(ts, CRC_TASK_STRUCT_MM);
    // we already checked that it is a user process in fill_syscall so
    // this should never be NULL
    if (mmptr == NULL) goto EmitWarning;

    void *exe = read_field_ptr(mmptr, CRC_MM_STRUCT_EXE_FILE);
    if (exe == NULL) goto EmitWarning;

    u64 arg_start = 0;
    if (read_field(mmptr, CRC_MM_STRUCT_ARG_START, &arg_start, sizeof(arg_start)) < 0)
        goto EmitWarning;

    u64 arg_end = 0;
    if (read_field(mmptr, CRC_MM_STRUCT_ARG_END, &arg_end, sizeof(arg_end)))
        goto EmitWarning;

    if (arg_end < arg_start) {
        error_info_t info = {0};
        info.argv.start = arg_start;
        info.argv.end = arg_end;
        set_local_warning(PMW_ARGV_INCONSISTENT, info);

        goto EmitWarning;
    }

    /* DONE WITH SANITY CHECKS - TIME TO FILL UP `pm` */

    pm->type = pm_type;
    pm->u.syscall_info.retcode = retcode;
    if (extract_file_info(exe, &pm->u.syscall_info.data.exec_info.file_info) < 0) goto EmitWarning;

    // TODO: handle error
    bpf_get_current_comm(&pm->u.syscall_info.data.exec_info.comm, sizeof(pm->u.syscall_info.data.exec_info.comm));

    /* SAVE ARGV */

    // length of all strings counting NULLs
    u64 argv_length = arg_end - arg_start;

    // manually truncate the length to half of the buffer so the ebpf
    // verifier knows for a fact we are not going over the bounds of
    // our buffer.
    const u64 MAX_ARGV_LENGTH = (MAX_PERCPU_BUFFER >> 1) - 1;
    if (argv_length > MAX_ARGV_LENGTH) {
        pm->u.syscall_info.data.exec_info.argv_truncated = 1;
        argv_length = MAX_ARGV_LENGTH;
    } else {
        pm->u.syscall_info.data.exec_info.argv_truncated = 0;
    }

    u32 offset = sizeof(process_message_t);
    pm->u.syscall_info.data.exec_info.buffer_length = offset;
    if (bpf_probe_read(&buffer->buf[offset], argv_length, (void *)arg_start) < 0) {
        error_info_t info = {0};
        info.argv.start = arg_start;
        info.argv.end = arg_end;
        set_local_warning(PMW_READ_ARGV, info);
        goto EmitWarning;
    }

    pm->u.syscall_info.data.exec_info.buffer_length += argv_length;

    // if for any reason the last character is not a NULL (e.g., we
    // truncated the argv not at a string boundary) make sure to
    // append a NULL to terminate the string
    if (buffer->buf[(pm->u.syscall_info.data.exec_info.buffer_length - 1) & (MAX_PERCPU_BUFFER - 1)] != '\0') {
        argv_length += 1; // we are taking up one more than we thought
        write_null_char(buffer, &pm->u.syscall_info.data.exec_info.buffer_length);
    }

    // do not rely on double NULL to separate argv from the rest. An
    // empty argument can also cause a double NULL.
    pm->u.syscall_info.data.exec_info.argv_length = argv_length;

    // append a NULL to signify the end of the argv
    // strings. Technically not necessary since we are passing
    // `argv_length` but it keeps it consistent with the other strings
    // in the buffer
    write_null_char(buffer, &pm->u.syscall_info.data.exec_info.buffer_length);

    /* FIND THE TOP DENTRY TO THE EXE */
    void *path = ptr_to_field(exe, CRC_FILE_F_PATH);
    if (path == NULL) goto EmitWarning;

    init_cached_path(cached_path, path);
    if (cached_path->next_dentry == NULL || cached_path->vfsmount == NULL) goto EmitWarning;

 ExeName:;
    /* WRITE EXE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, cached_path, buffer, tail_call);

    // reset skips back to 0. This will automatically update it in the
    // map so no need to do a bpf_map_update_elem.
    cached_path->next_dentry = NULL;
    if (ret < 0) goto EmitWarning;

    // add an extra null byte to signify string section end
    write_null_char(buffer, &pm->u.syscall_info.data.exec_info.buffer_length);

    /* PROCESS PWD IN A TAIL CALL  */
    bpf_tail_call(ctx, &tail_call_table, SYS_EXEC_PWD);

    // if we fail to tail call we still got quite a bit of information
    // so let's push what we have
    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

    // but still emit a warning afterwards
    error_info_t info = {0};
    info.tailcall = tail_call;
    set_local_warning(PMW_TAIL_CALL_MAX, info);

 EmitWarning:;
    cached_path->next_dentry = NULL;

    push_warning(ctx, pm, pm_type);
}

static __always_inline void process_pwd(struct pt_regs *ctx)
{
  /* SETUP ALL THE VARIABLES THAT WILL BE NEEDED ACCROSS GOTOS */

    u32 key = 0;
    buf_t *buffer = (buf_t *)bpf_map_lookup_elem(&buffers, &key);
    if (buffer == NULL) return;

    cached_path_t *cached_path = (cached_path_t *)bpf_map_lookup_elem(&percpu_path, &key);
    if (cached_path == NULL) return;

    int ret = 0;
    process_message_t *pm = (process_message_t *)buffer;
    process_message_type_t pm_type = pm->type;

    if (cached_path->next_dentry != NULL) goto Pwd;

    /* FIND THE TOP DENTRY TO THE PWD */

    void *ts = (void *)bpf_get_current_task();

    // set ret to error to handle any going to Done early
    ret = -1;
    // task_struct->fs
    void *path = path = read_field_ptr(ts, CRC_TASK_STRUCT_FS);
    if (path == NULL) goto Done;

    // &(task_struct->fs->pwd)
    path = ptr_to_field(path, CRC_FS_STRUCT_PWD);
    if (path == NULL) goto Done;

    init_cached_path(cached_path, path);
    if (cached_path->next_dentry == NULL || cached_path->vfsmount == NULL) goto Done;

 Pwd:;
    /* WRITE PATH; IT MAY TAIL CALL */
    ret = write_path(ctx, cached_path, buffer, SYS_EXEC_PWD);

 Done:;
    /* PUSH THE EVENT AND RESET */
    cached_path->next_dentry = NULL;

    // add an extra null byte to signify string section end
    write_null_char(buffer, &pm->u.syscall_info.data.exec_info.buffer_length);
    push_flexible_message(ctx, pm, pm->u.syscall_info.data.exec_info.buffer_length);

    if (ret < 0) push_warning(ctx, pm, pm_type);
}
