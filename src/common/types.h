// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause

#pragma once

#include <linux/types.h>
#include <linux/limits.h>
#include <linux/version.h>

#define MAX_ADDRESSES 16
#define TRUE 1
#define FALSE 0

// Had to add these for some reason
#define TASK_COMM_LEN 16
typedef __u16 u16;

#ifndef _UAPI_LINUX_IN6_H
struct in6_addr
{
    union
    {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};
#endif

#define ETH_ALEN 6
struct ethhdr
{
    unsigned char h_dest[ETH_ALEN];   /* destination eth addr	*/
    unsigned char h_source[ETH_ALEN]; /* source ether addr	*/
    __be16 h_proto;                   /* packet type ID field	*/
} __attribute__((packed));

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
    SP_EXECVEAT,
} syscall_pattern_type_t;

typedef enum
{
    W_UNSPEC,
    W_BUFFER_FULL,
    W_TAIL_CALL_MAX,
    W_UPDATE_MAP_ERROR,
    W_PID_TGID_MISMATCH,
    W_UNEXPECTED,
    W_READ_PATH_STRING,
    W_READ_ARGV,
    W_READING_FIELD,
    W_ARGV_INCONSISTENT,
    W_PTR_FIELD_READ,
    W_NULL_FIELD,
    W_INTERP_MISMATCH,
    W_INTERP_SLOT,
    W_NO_DENTRY,
} warning_t;

typedef enum
{
    PM_UNSPEC,
    PM_EXIT,
    PM_EXITGROUP,
    PM_UNSHARE,
    PM_CLONE,
    PM_CLONE3,
    PM_FORK,
    PM_VFORK,
    PM_EXECVE,
    PM_EXECVEAT,
    PM_WARNING,
    PM_SCRIPT,
} process_message_type_t;

typedef enum
{
    FM_UNSPEC,
    FM_CREATE,
    FM_DELETE,
    FM_MODIFY,
    FM_RENAME,
    FM_WARNING,
} file_message_type_t;

typedef union
{
    process_message_type_t process;
    file_message_type_t file;
} message_type_t;

#define COMMON_FIELDS                           \
    u32 pid;                                    \
    u32 tid;                                    \
    u64 mono_ns;                                \
    u32 ppid;                                   \
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

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#ifndef MAJOR
#define MAJOR(dev) ((unsigned int)((dev) >> MINORBITS))
#endif

#ifndef MINOR
#define MINOR(dev) ((unsigned int)((dev)&MINORMASK))
#endif

typedef struct
{
    u32 devmajor;
    u32 devminor;
    u64 inode;
} file_info_t, *pfile_info_t;

typedef struct
{
    u32 uid;
    u32 gid;
    u32 mode;
} file_ownership_t;

typedef enum
{
    LINK_NONE,
    LINK_SYMBOLIC,
    LINK_HARD,
} file_link_type_t;

typedef struct
{
    u32 child_pid;
    u64 flags;
} clone_info_t;

typedef struct
{
    // whether argv_length is truncated from the actual length. This
    // is just here so userspace knows that the argv sent is not the
    // entirety of the argv but just our best effort.
    u8 argv_truncated;
    // send the length of argv we are processing. This is
    // necessary because unlike paths, argvs can have empty
    // strings so we cannot rely on double null separators
    u16 argv_length;
    u32 buffer_length;
    u64 event_id;
    u64 cgroup_id;
    file_info_t file_info;
    char comm[TASK_COMM_LEN];
} exec_info_t;

typedef union
{
    u32 unshare_flags;
    clone_info_t clone_info;
    exec_info_t  exec_info;
} syscall_data_t;

typedef struct
{
    u32 pid;
    u32 ppid;
    u32 luid;
    u32 euid;
    u32 egid;
    int retcode;
    u64 mono_ns;
    syscall_data_t data;
} syscall_info_t, *psyscall_info_t;

enum direction_t
{
    inbound,
    outbound,
    nowhere
};

struct process_data
{
    u32 pid;
    char comm[TASK_COMM_LEN];
};

typedef union
{
    struct
    {
        __be32 dest_addr;
        __be32 src_addr;
    } ipv4;
    struct
    {
        struct in6_addr dest_addr;
        struct in6_addr src_addr;
    } ipv6;
} ip_addr_t;

typedef struct
{
    u16 protocol_type;           // Something like IPPROTO_TCP or IPPROTO_UDP
    u16 ip_type;                 // AF_INET or AF_INET6
    u16 dest_port;
    u16 src_port;
    enum direction_t direction;  // inbound or outbound
    struct process_data process; // pid and comm string
    u64 mono_ns;                 // Timestamp
    ip_addr_t protos;
} network_event_t, *pnetwork_event_t;

typedef enum
{
    RET_SYS_EXECVEAT,
    RET_SYS_EXECVE,
    SYS_EXEC_PWD,
    RET_DO_MKDIRAT,
    HANDLE_PWD,
} tail_call_slot_t;

typedef union
{
    int err;
    u64 stored_pid_tgid;
    u64 offset_crc;
    struct {
        u64 start;
        u64 end;
    } argv;
    tail_call_slot_t tailcall;
} error_info_t;

typedef struct
{
    warning_t code;
    message_type_t message_type;
    u64 pid_tgid;
    error_info_t info;
} warning_info_t;

typedef struct
{
    u32 buffer_length;
    u64 event_id;
    file_info_t scripts[4];
} script_info_t;

typedef union
{
    syscall_info_t syscall_info;
    warning_info_t warning_info;
    script_info_t script_info;
} process_message_data_t;

typedef struct
{
    process_message_type_t type;
    process_message_data_t u;
    // not allowed inside union
    char strings[];
} process_message_t, *pprocess_message_t;

#define MAX_PATH_SEG 64
typedef struct {
    int current_state;
    char path_segment[MAX_PATH_SEG];
} filter_key_t;

typedef struct {
    int next_state;
    int tag;
} filter_value_t;

typedef struct
{
    u32 pid;
    u64 mono_ns;
    u32 buffer_len;
    file_info_t target;
    file_ownership_t target_owner;
    u32 tag;
    union {
        struct {
            file_link_type_t source_link;
        } create;
        struct {
            file_ownership_t before_owner;
        } modify;
        struct {
            file_info_t source;
            file_info_t overwr;
            file_ownership_t overwr_owner;
        } rename;
    } u;
} file_action_t;

typedef union
{
    file_action_t action;
    warning_info_t warning;
} file_message_data_t;

typedef struct
{
    file_message_type_t type;
    file_message_data_t u;
    char strings[];
} file_message_t, *pfile_message_t;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
// clone3 args are not available in sched.h until 5.3, and we build against 4.4
struct clone_args
{
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
#endif
