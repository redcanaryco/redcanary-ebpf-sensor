// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause

#pragma once

#include <linux/types.h>
#include <linux/limits.h>

#define MAX_ADDRESSES 16
#define TRUE 1
#define FALSE 0

/*
 * This number was determined experimentally, setting it higher will exceed
 * the BPF 512 byte stack limit.
 */
#define VALUE_SIZE 144UL

typedef enum
{
    PAM_SERVICE = 1,       /* The service name */
    PAM_USER = 2,          /* The user name */
    PAM_TTY = 3,           /* The tty name */
    PAM_RHOST = 4,         /* The remote host name */
    PAM_CONV = 5,          /* The pam_conv structure */
    PAM_AUTHTOK = 6,       /* The authentication token (password) */
    PAM_OLDAUTHTOK = 7,    /* The old authentication token */
    PAM_RUSER = 8,         /* The remote user name */
    PAM_USER_PROMPT = 9,   /* the prompt for getting a username -PAM extensions */
    PAM_FAIL_DELAY = 10,   /* app supplied function to override failure delays */
    PAM_XDISPLAY = 11,     /* X display name */
    PAM_XAUTHDATA = 12,    /* X server authentication data */
    PAM_AUTHTOK_TYPE = 13, /* The type for pam_get_authtok */
} pam_item_type_t;

typedef enum
{
    SP_IGNORE,
    SP_USERMODE,
    SP_OPEN_WRITE_PROC_MEM,
    SP_PROCESS_VM_WRITEV,
    SP_PTRACE_POKETEXT,
    SP_PTRACE_POKEDATA,
    SP_PTRACE_SETREGS,
    SP_PTRACE_SETREGSET,
    SP_PTRACE_POKEUSR,
    SP_PTRACE_ATTACH,
    SP_PTRACE_SEIZE,
    SP_PTRACE_SET_SYSCALL,
    SP_MPROTECT,
    SP_PKEY_MPROTECT,
    SP_MOUNT,
    SP_SETUID,
    SP_SETGID,
    SP_SETREUID,
    SP_SETREGID,
    SP_SETRESUID,
    SP_SETRESGID,
    SP_EXIT,
    SP_EXITGROUP,
    SP_UNSHARE,
    SP_CLONE,
    SP_CLONE3,
    SP_FORK,
    SP_VFORK,
    SP_EXECVE,
    SP_EXECVEAT,
} syscall_pattern_type_t;

typedef enum
{
    TE_UNSPEC,
    TE_SYSCALL_INFO,
    TE_EXE_PATH,
    TE_PATH,
    TE_COMMAND_LINE,
    TE_ENVIRONMENT,
    TE_CURRENT_WORKING_DIRECTORY,
    TE_FILE_INFO,
    TE_RETCODE,
    TE_CLONE_INFO,
    TE_CLONE3_INFO,
    TE_UNSHARE_FLAGS,
    TE_EXIT_STATUS,
    TE_EXEC_FILENAME,
    TE_PWD,
} telemetry_event_type_t;

#define COMMON_FIELDS \
    u32 pid;          \
    u32 tid;          \
    u64 mono_ns;      \
    u32 ppid;         \
    syscall_pattern_type_t syscall_pattern;

typedef struct
{
    COMMON_FIELDS;
    u32 target_pid;
    u32 _pad;
} trace_process_event_t;

typedef struct
{
    COMMON_FIELDS;
    u32 target_pid;
    u64 addresses[MAX_ADDRESSES];
} write_process_memory_event_t;

typedef struct
{
    COMMON_FIELDS;
    u64 address;
    u64 len;
    u32 prot;
    u32 _pad;
} change_memory_permission_event_t;

typedef struct
{
    COMMON_FIELDS;
    u64 flags;
    u8 source[128];
    u8 target[128];
    u8 fs_type[16];
    u8 data[64];
} mount_event_t;

typedef struct
{
    COMMON_FIELDS;
    u32 current_ruid;
    u32 current_rgid;
    u32 euid;
    u32 egid;
    u32 ruid;
    u32 rgid;
    u32 suid;
    u32 sgid;
} credentials_event_t;

typedef enum
{
    PAM_START,
    PAM_AUTHENTICATE,
    PAM_CHAUTHTOK,
    PAM_SET_ITEM,
    PAM_SET_CRED,
    PAM_END,
} pam_stage_t;

typedef struct
{
    u8 service_name[128];
    u8 user_name[128];
} pam_start_t;

typedef struct
{
    pam_item_type_t item_type;
    u8 data[256];
} pam_set_item_t;

typedef struct
{
    COMMON_FIELDS;
    u64 pam_handle;
    pam_stage_t stage;
    u32 result;
    u32 flags;
    union
    {
        pam_start_t pam_start;
        pam_set_item_t pam_set_item;
    } u;

} pam_event_t;

typedef struct
{
    COMMON_FIELDS;
    char value[384];
} read_return_string_event_t;


#ifndef MAJOR
#define MAJOR(dev)	((dev)>>8)
#endif

#ifndef MINOR
#define MINOR(dev)	((dev) & 0xff)
#endif

typedef struct {
    u64 inode;
    u32 devmajor;
    u32 devminor;
    char value[VALUE_SIZE];
} file_info_t, *pfile_info_t;

typedef struct
{
    u32 new_pid;
    u64 fork_flags;
} process_fork_info_t;

typedef struct
{

} netconn_info_t;

typedef struct 
{
    COMMON_FIELDS;
    u32 luid;
    u32 euid;
    u32 egid;
    char comm[16];
} syscall_info_t, *psyscall_info_t;

typedef struct
{
    u64 flags;
    u64 stack;
    u32 parent_tid;
    u32 child_tid;
    u64 tls;
    u64 p_ptr;
    u64 c_ptr;
} clone_info_t, *pclone_info_t;

typedef struct
{
    u64 flags;
    u64 pidfd;
    u64 child_tid;
    u64 parent_tid;
    u64 exit_signal;
    u64 stack;
    u64 stack_size;
    u64 tls;
    u64 set_tid;
    u64 set_tid_size;
    u64 cgroup;
    u64 c_ptr;
    u64 p_ptr;
    u64 size;
} clone3_info_t, *pclone3_info_t;

typedef struct
{
    u64 id;
    u32 done;
    telemetry_event_type_t telemetry_type;
    union {
        syscall_info_t syscall_info; 
        file_info_t file_info;
        clone_info_t clone_info;
        clone3_info_t clone3_info;
        int unshare_flags;
        int exit_status;
        struct {
            char value[VALUE_SIZE];
            char truncated;
        } v;
        u64 retcode;
    } u;
} telemetry_event_t, *ptelemetry_event_t;

// clone3 args are not available in sched.h until 5.3, and we build against 4.4
struct clone_args {
    __aligned_u64 flags;
    __aligned_u64 pidfd;
    __aligned_u64 child_tid;
    __aligned_u64 parent_tid;
    __aligned_u64 exit_signal;
    __aligned_u64 stack;
    __aligned_u64 stack_size;
    __aligned_u64 tls;
    // version 2
    __aligned_u64 set_tid;
    __aligned_u64 set_tid_size;
    // version 3
    __aligned_u64 cgroup;
};

typedef enum {
    SYS_EXECVE_4_8,
    SYS_EXECVEAT_4_8,
    SYS_EXEC_TC_ARGV,
    SYS_EXEC_TC_ENVP,
    RET_SYS_EXECVE,
    RET_SYS_CLONE,
    RET_SYS_CLONE3,
    RET_SYS_UNSHARE,
    RET_SYS_EXIT,
} tail_call_slot_t;