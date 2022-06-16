// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause

#pragma once

#include <linux/types.h>
#include <linux/limits.h>

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
    SP_EXECVEAT,
} syscall_pattern_type_t;

typedef enum {
    PMW_BUFFER_FULL = 1,
    PMW_TAIL_CALL_MAX,
    PMW_MAX_PATH,
    PMW_DOUBLE_EXEC,
    PMW_FILLED_EVENTS,
    PMW_WRONG_TYPE,
    PMW_UNEXPECTED,
} process_message_warning_t;

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
    PM_STRINGS,
    PM_DISCARD,
    PM_WARNING,
} process_message_type_t;

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
    char comm[TASK_COMM_LEN];
} file_info_t, *pfile_info_t;

typedef struct {
    u32 child_pid;
    u64 flags;
} clone_info_t;

typedef struct
{
    u32 pid;
    u32 ppid;
    u32 luid;
    u32 euid;
    u32 egid;
    int retcode;
    u64 mono_ns;
    union {
        u32 unshare_flags;
        clone_info_t clone_info;
        struct {
            u64 event_id;
            u32 buffer_length;
            file_info_t file_info;
        } exec_info;
    } data;
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

typedef struct
{
    u64 mono_ns;
    struct process_data process;
    char path[128];
} script_info_t;

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
    enum direction_t direction;  // inbound or outbound
    struct process_data process; // pid and comm string
    u64 mono_ns;                 // Timestamp
    u16 dest_port;
    u16 src_port;
    ip_addr_t protos;
} network_event_t, *pnetwork_event_t;

typedef struct {
    char value[VALUE_SIZE];
    char truncated;
} telemetry_value_t;

typedef struct
{
    process_message_type_t type;
    union {
        syscall_info_t syscall_info;
        struct {
            u64 event_id;
            u32 buffer_length;
        } string_info;
        struct {
            u64 event_id;
        } discard_info;
    } u;
    // not allowed inside union
    char strings[];
} process_message_t, *pprocess_message_t;

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

typedef enum
{
    SYS_EXECVE_4_11,
    SYS_EXECVEAT_4_11,
    RET_SYS_EXECVEAT_4_8,
    SYS_EXECVE_TC_ARGV,
    SYS_EXECVEAT_TC_ARGV,
    HANDLE_PWD,
} tail_call_slot_t;

typedef enum {
    SM_PWD,
    SM_SCRIPT,
    SM_CHAR_STR,
} script_message_type_t;

typedef struct {
    u32 event_id;
    script_message_type_t type;
    union {
        script_info_t script_info;
        telemetry_value_t v;
    } u;
} script_message_t, *pscript_message_t;
