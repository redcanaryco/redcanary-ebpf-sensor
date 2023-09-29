// SPDX-License-Identifier: GPL-2.0+

#pragma once

#define __BPF_EXT_FUNC_MAPPER(FN)           \
    FN(unspec),                             \
        FN(map_lookup_elem),                \
        FN(map_update_elem),                \
        FN(map_delete_elem),                \
        FN(probe_read),                     \
        FN(ktime_get_ns),                   \
        FN(trace_printk),                   \
        FN(get_prandom_u32),                \
        FN(get_smp_processor_id),           \
        FN(skb_store_bytes),                \
        FN(l3_csum_replace),                \
        FN(l4_csum_replace),                \
        FN(tail_call),                      \
        FN(clone_redirect),                 \
        FN(get_current_pid_tgid),           \
        FN(get_current_uid_gid),            \
        FN(get_current_comm),               \
        FN(get_cgroup_classid),             \
        FN(skb_vlan_push),                  \
        FN(skb_vlan_pop),                   \
        FN(skb_get_tunnel_key),             \
        FN(skb_set_tunnel_key),             \
        FN(perf_event_read),                \
        FN(redirect),                       \
        FN(get_route_realm),                \
        FN(perf_event_output),              \
        FN(skb_load_bytes),                 \
        FN(get_stackid),                    \
        FN(csum_diff),                      \
        FN(skb_get_tunnel_opt),             \
        FN(skb_set_tunnel_opt),             \
        FN(skb_change_proto),               \
        FN(skb_change_type),                \
        FN(skb_under_cgroup),               \
        FN(get_hash_recalc),                \
        FN(get_current_task),               \
        FN(probe_write_user),               \
        FN(current_task_under_cgroup),      \
        FN(skb_change_tail),                \
        FN(skb_pull_data),                  \
        FN(csum_update),                    \
        FN(set_hash_invalid),               \
        FN(get_numa_node_id),               \
        FN(skb_change_head),                \
        FN(xdp_adjust_head),                \
        FN(probe_read_str),                 \
        FN(get_socket_cookie),              \
        FN(get_socket_uid),                 \
        FN(set_hash),                       \
        FN(setsockopt),                     \
        FN(skb_adjust_room),                \
        FN(redirect_map),                   \
        FN(sk_redirect_map),                \
        FN(sock_map_update),                \
        FN(xdp_adjust_meta),                \
        FN(perf_event_read_value),          \
        FN(perf_prog_read_value),           \
        FN(getsockopt),                     \
        FN(override_return),                \
        FN(sock_ops_cb_flags_set),          \
        FN(msg_redirect_map),               \
        FN(msg_apply_bytes),                \
        FN(msg_cork_bytes),                 \
        FN(msg_pull_data),                  \
        FN(bind),                           \
        FN(xdp_adjust_tail),                \
        FN(skb_get_xfrm_state),             \
        FN(get_stack),                      \
        FN(skb_load_bytes_relative),        \
        FN(fib_lookup),                     \
        FN(sock_hash_update),               \
        FN(msg_redirect_hash),              \
        FN(sk_redirect_hash),               \
        FN(lwt_push_encap),                 \
        FN(lwt_seg6_store_bytes),           \
        FN(lwt_seg6_adjust_srh),            \
        FN(lwt_seg6_action),                \
        FN(rc_repeat),                      \
        FN(rc_keydown),                     \
        FN(skb_cgroup_id),                  \
        FN(get_current_cgroup_id),          \
        FN(get_local_storage),              \
        FN(sk_select_reuseport),            \
        FN(skb_ancestor_cgroup_id),         \
        FN(sk_lookup_tcp),                  \
        FN(sk_lookup_udp),                  \
        FN(sk_release),                     \
        FN(map_push_elem),                  \
        FN(map_pop_elem),                   \
        FN(map_peek_elem),                  \
        FN(msg_push_data),                  \
        FN(msg_pop_data),                   \
        FN(rc_pointer_rel),                 \
        FN(spin_lock),                      \
        FN(spin_unlock),                    \
        FN(sk_fullsock),                    \
        FN(tcp_sock),                       \
        FN(skb_ecn_set_ce),                 \
        FN(get_listener_sock),              \
        FN(skc_lookup_tcp),                 \
        FN(tcp_check_syncookie),            \
        FN(sysctl_get_name),                \
        FN(sysctl_get_current_value),       \
        FN(sysctl_get_new_value),           \
        FN(sysctl_set_new_value),           \
        FN(strtol),                         \
        FN(strtoul),                        \
        FN(sk_storage_get),                 \
        FN(sk_storage_delete),              \
        FN(send_signal),                    \
        FN(tcp_gen_syncookie),              \
        FN(skb_output),                     \
        FN(probe_read_user),                \
        FN(probe_read_kernel),              \
        FN(probe_read_user_str),            \
        FN(probe_read_kernel_str),          \
        FN(tcp_send_ack),                   \
        FN(send_signal_thread),             \
        FN(jiffies64),                      \
        FN(read_branch_records),            \
        FN(get_ns_current_pid_tgid),        \
        FN(xdp_output),                     \
        FN(get_netns_cookie),               \
        FN(get_current_ancestor_cgroup_id), \
        FN(sk_assign),                      \
        FN(ktime_get_boot_ns),              \
        FN(seq_printf),                     \
        FN(seq_write),                      \
        FN(sk_cgroup_id),                   \
        FN(sk_ancestor_cgroup_id),          \
        FN(ringbuf_output),                 \
        FN(ringbuf_reserve),                \
        FN(ringbuf_submit),                 \
        FN(ringbuf_discard),                \
        FN(ringbuf_query),                  \
        FN(csum_level),                     \
        FN(skc_to_tcp6_sock),               \
        FN(skc_to_tcp_sock),                \
        FN(skc_to_tcp_timewait_sock),       \
        FN(skc_to_tcp_request_sock),        \
        FN(skc_to_udp6_sock),               \
        FN(get_task_stack),                 \
        FN(load_hdr_opt),                   \
        FN(store_hdr_opt),                  \
        FN(reserve_hdr_opt),                \
        FN(inode_storage_get),              \
        FN(inode_storage_delete),           \
        FN(d_path),                         \
        FN(copy_from_user),                 \
        FN(snprintf_btf),                   \
        FN(seq_printf_btf),                 \
        FN(skb_cgroup_classid),             \
        FN(redirect_neigh),                 \
        FN(per_cpu_ptr),                    \
        FN(this_cpu_ptr),                   \
        FN(redirect_peer),                  \
        FN(task_storage_get),               \
        FN(task_storage_delete),            \
        FN(get_current_task_btf),           \
        FN(bprm_opts_set),                  \
        FN(ktime_get_coarse_ns),            \
        FN(ima_inode_hash),                 \
        FN(sock_from_file),

#define __BPF_EXT_ENUM_FN(x) BPF_EXT_FUNC_##x
enum bpf_ext_func_id
{
    __BPF_EXT_FUNC_MAPPER(__BPF_EXT_ENUM_FN)
};
#undef __BPF_EXT_ENUM_FN

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
    (void *)BPF_EXT_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) =
    (void *)BPF_EXT_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
    (void *)BPF_EXT_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
    (void *)BPF_EXT_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
    (void *)BPF_EXT_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
    (void *)BPF_EXT_FUNC_trace_printk;
static unsigned long long (*bpf_get_smp_processor_id)(void) =
    (void *)BPF_EXT_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
    (void *)BPF_EXT_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
    (void *)BPF_EXT_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
    (void *)BPF_EXT_FUNC_get_current_comm;
static int (*bpf_perf_event_read)(void *map, int index) =
    (void *)BPF_EXT_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
    (void *)BPF_EXT_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
    (void *)BPF_EXT_FUNC_redirect;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, int size) =
    (void *)BPF_EXT_FUNC_perf_event_output;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
    (void *)BPF_EXT_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
    (void *)BPF_EXT_FUNC_skb_set_tunnel_key;
static unsigned long long (*bpf_get_prandom_u32)(void) =
    (void *)BPF_EXT_FUNC_get_prandom_u32;
static long (*bpf_probe_read_str)(void *dst, u32 size, const void *unsafe_ptr) =
    (void *)BPF_EXT_FUNC_probe_read_str;
static int (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_EXT_FUNC_probe_read_user;
static int (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_EXT_FUNC_probe_read_kernel;
static int (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_EXT_FUNC_probe_read_user_str;
static int (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) =
    (void *)BPF_EXT_FUNC_probe_read_kernel_str;
static unsigned long long (*bpf_get_current_task)(void) =
    (void *)BPF_EXT_FUNC_get_current_task;
static unsigned long long (*bpf_tail_call)(void *ctx, void *map, int index) =
    (void *)BPF_EXT_FUNC_tail_call;
static u64 (*bpf_get_current_cgroup_id)(void) =
    (void *)BPF_EXT_FUNC_get_current_cgroup_id;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
#define BUF_SIZE_MAP_NS 256

struct bpf_map_def
{
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int pinning;
    char namespace[BUF_SIZE_MAP_NS];
};

#define BPF_CORE_READ(src, a)     \
	({							  \
        typeof((src)->a) __val;   \
        bpf_probe_read_kernel((void *) &__val , sizeof(__val), (&((typeof((src)))(src))->a));  \
		__val;					  \
	})

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

#include "bpf_tracing.h"
