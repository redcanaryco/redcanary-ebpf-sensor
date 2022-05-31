#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include "types.h"
#include "offsets.h"
#include "common.h"

typedef void *_skbuff;
typedef void *_sock;

// Just doing a simple 16-bit byte swap
#define SWAP_U16(x) (((x) >> 8) | ((x) << 8))

struct bpf_map_def SEC("maps/tcp_connect") tcp_connect = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udp_outgoing_map") udp_outgoing_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/network_events") network_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // let oxidebpf set it to num_cpus
    .pinning = 0,
    .namespace = "",
};

// A helper function for getting the pointer to the sk_buff
static __always_inline int save_sock_ptr(struct pt_regs *ctx, void *map)
{
    _skbuff sk = (_skbuff)PT_REGS_PARM1(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(map, &index, &sk, BPF_ANY);

    return 0;
}

// Network connections will only emit once per "shape", the shape
// being the `network_event_key_t`. This is done to prevent
// overloading userspace with repetitive network connections by the
// same process (e.g., a chatty UDP connection). Not including UDP vs
// TCP because it's embedded in remote_port (always 0 for UDP; never 0
// for TCP). Not including ipv4 vs ipv6 because it is embedded in
// ip_addr_t
typedef struct {

    u16 remote_port;
    u32 pid;
    ip_addr_t protos;
} network_event_key_t;

struct bpf_map_def SEC("maps/lru_hash") lru_hash = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(network_event_key_t),
    .value_size = sizeof(u8),
    .max_entries = 8*1024,
    .pinning = 0,
    .namespace = "",
};

static __always_inline int push_event(void *ctx, network_event_t *data) {
    network_event_key_t key = {0};
    key.pid = data->process.pid;
    key.protos = data->protos;
    key.remote_port = data->protocol_type == IPPROTO_UDP ? 0 : data->dest_port;

    if (bpf_map_lookup_elem(&lru_hash, &key) != NULL) {
        return 0;
    }

    int result = bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, data, sizeof(network_event_t));
    // only add to cache if the event is successfully added to the
    // output. This is done so in the case of the buffer being full we
    // may still be able to submit a future event of the same shape
    // later.
    if (result == 0) {
        u8 exists = 1;
        bpf_map_update_elem(&lru_hash, &key, &exists, BPF_ANY);
    }
    return result;
}

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
    _sock sk = (_sock)PT_REGS_PARM1(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tcp_connect, &index, &sk, BPF_ANY);

    return 0;
}

SEC("kprobe/ip_local_out")
int kprobe__ip_local_out(struct pt_regs *ctx)
{
    _skbuff sk = (_skbuff)PT_REGS_PARM3(ctx);
    u32 index = (u32)bpf_get_current_pid_tgid();

    bpf_map_update_elem(&udp_outgoing_map, &index, &sk, BPF_ANY);

    return 0;
}

SEC("kprobe/udp_outgoing")
int kprobe__udp_outgoing(struct pt_regs *ctx)
{
    return save_sock_ptr(ctx, &udp_outgoing_map);
}

SEC("kretprobe/ret_inet_csk_accept")
int kretprobe__ret_inet_csk_accept(struct pt_regs *ctx)
{
    // Get the return value from inet_csk_accept
    unsigned char *sk_base = (unsigned char *)PT_REGS_RC(ctx);

    // Just to be safe 0 out the structs
    network_event_t ev = {0};

    // Initialize some of the telemetry event
    ev.mono_ns = bpf_ktime_get_ns();

    if (sk_base == NULL)
    {
        return 0;
    }

    ev.direction = inbound;
    ev.protocol_type = IPPROTO_TCP;

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    int ret = read_value(sk_base, CRC_SOCK_COMMON_FAMILY, &ev.ip_type, sizeof(ev.ip_type));
    if (ret == -1)
    {
        return 0;
    }

    if (ev.ip_type == AF_INET && loaded)
    {
        // The dest and src are intentionally backwards
        read_value(sk_base, CRC_SOCK_COMMON_SADDR, &ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr));
        read_value(sk_base, CRC_SOCK_COMMON_DADDR, &ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SPORT, &ev.dest_port, sizeof(ev.dest_port));
        read_value(sk_base, CRC_SOCK_COMMON_DPORT, &ev.src_port, sizeof(ev.src_port));
        ev.src_port = SWAP_U16(ev.src_port);
    }
    else if (ev.ip_type == AF_INET6 && loaded)
    {
        // The dest and src are intentionally backwards
        read_value(sk_base, CRC_SOCK_COMMON_SADDR6, &ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr));
        read_value(sk_base, CRC_SOCK_COMMON_DADDR6, &ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SPORT, &ev.dest_port, sizeof(ev.dest_port));
        read_value(sk_base, CRC_SOCK_COMMON_DPORT, &ev.src_port, sizeof(ev.src_port));
        ev.src_port = SWAP_U16(ev.src_port);
    } else {
        return 0;
    }

    // Get Process data and set pid and comm string
    ev.process.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(ev.process.comm, sizeof(ev.process.comm));

    // Output data to generator
    push_event(ctx, &ev);

    return 0;
}

// This handles both IPv4 and IPv6 udp packets
SEC("kretprobe/ret___skb_recv_udp")
int kretprobe__ret___skb_recv_udp(struct pt_regs *ctx)
{
    // Just to be safe 0 out the structs
    network_event_t ev = {0};

    // Initialize some of the network event
    ev.mono_ns = bpf_ktime_get_ns();
    ev.protocol_type = IPPROTO_UDP;

    _skbuff skb = (_skbuff)PT_REGS_RC(ctx);
    unsigned char *skbuff_base = (unsigned char *)skb;

    if (skbuff_base == NULL)
    {
        return 0;
    }

    ev.direction = inbound;
    ev.protocol_type = IPPROTO_UDP;

    // Get current pid
    ev.process.pid = (u32)(bpf_get_current_pid_tgid() >> 32);

    unsigned char *skb_head = NULL;
    unsigned short mac_header = 0;
    unsigned short transport_header = 0;
    unsigned short network_header = 0;
    __be16 proto = 0;

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);

    int ret = read_value(skbuff_base, CRC_SKBUFF_HEAD, &skb_head, sizeof(skb_head));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_SKBUFF_MAC_HDR, &mac_header, sizeof(mac_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_SKBUFF_PROTO, &proto, sizeof(proto));
    if (ret == -1)
    {
        return 0;
    }

    u64 eth_proto_offset = CRC_SKBUFF_PROTO;
    eth_proto_offset = (u64)bpf_map_lookup_elem(&offsets, &eth_proto_offset);

    struct ethhdr *eth = (struct ethhdr *)(skb_head + mac_header);
    struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
    struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
    // bpf_probe_read(&version, sizeof(version), (void *)(ip));
    // version = ((version & 0xf0) >> 4); // Get the upper 4 bits
    bpf_probe_read(&proto, sizeof(proto), (void *)(&eth->h_proto));
    if (proto == 0x8)
    {
        ev.ip_type = AF_INET;
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ip->protocol));
        proto = proto & 0xff;

        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr), (void *)(&ip->daddr));
            bpf_probe_read(&ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr), (void *)(&ip->saddr));
        }
        else
        {
            // If it is not udp we don't care
            return 0;
        }
    }
    else if (proto == 0xdd86)
    {
        ev.ip_type = AF_INET6;
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(skb_head + network_header);
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ipv6->nexthdr));
        proto = proto & 0xff;
        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr), (void *)(&ipv6->daddr));
            bpf_probe_read(&ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr), (void *)(&ipv6->saddr));
        }
        else
        {
            // If it is not udp we don't care
            return 0;
        }
    }
    else
    {
        return 0;
    }
    bpf_probe_read(&ev.dest_port, sizeof(ev.dest_port), (void *)(&udp->dest));
    bpf_probe_read(&ev.src_port, sizeof(ev.src_port), (void *)(&udp->source));
    ev.src_port = SWAP_U16(ev.src_port);
    ev.dest_port = SWAP_U16(ev.dest_port);

    // Get Process data and set pid and comm string

    bpf_get_current_comm(ev.process.comm, sizeof(ev.process.comm));

    // Output data to generator
    push_event(ctx, &ev);
    return 0;
}

// This handles outgoing udp packets
SEC("kretprobe/ret_udp_outgoing")
int kretprobe__ret_udp_outgoing(struct pt_regs *ctx)
{
    unsigned char *skb_head = NULL;
    unsigned short transport_header = 0;
    unsigned short network_header = 0;
    unsigned char proto = 0;
    unsigned char version = 0;
    _skbuff *skpp;

    int ret = PT_REGS_RC(ctx);
    if (ret < 0)
    {
        return 0;
    }

    // Just to be safe 0 out the structs
    network_event_t ev = {0};

    // Initialize some of the network event
    ev.mono_ns = bpf_ktime_get_ns();
    ev.protocol_type = IPPROTO_UDP;
    ev.direction = outbound;

    // Get current pid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 index = (u32)pid_tgid;

    ev.process.pid = (u32)(pid_tgid >> 32);

    // Lookup the corresponding sk_buff* that we saved when udp_outgoing
    skpp = bpf_map_lookup_elem(&udp_outgoing_map, &index);
    if (skpp == NULL)
    {
        return 0;
    }
    bpf_map_delete_elem(&udp_outgoing_map, &index);

    unsigned char *skbuff_base = (unsigned char *)*skpp;
    if (skbuff_base == NULL)
    {
        return 0;
    }

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    if (!loaded)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_SKBUFF_HEAD, &skb_head, sizeof(skb_head));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header));
    if (ret == -1)
    {
        return 0;
    }

    ret = read_value(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header));
    if (ret == -1)
    {
        return 0;
    }

    struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
    struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
    bpf_probe_read(&version, sizeof(version), (void *)(ip));
    version = ((version & 0xf0) >> 4); // Get the upper 4 bits

    if (version == 4)
    {
        ev.ip_type = AF_INET;
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ip->protocol));
        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr), (void *)(&ip->daddr));
            bpf_probe_read(&ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr), (void *)(&ip->saddr));
        }
        else
        {
            // If it is not udp we don't care
            return 0;
        }
    }
    else if (version == 6)
    {
        ev.ip_type = AF_INET6;
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(skb_head + network_header);
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ipv6->nexthdr));
        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr), (void *)(&ipv6->daddr));
            bpf_probe_read(&ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr), (void *)(&ipv6->saddr));
        }
        else
        {
            // If it is not udp we don't care
            return 0;
        }
    }
    else
    {
        // We should not ever get here
        return 0;
    }
    bpf_probe_read(&ev.dest_port, sizeof(ev.dest_port), (void *)(&udp->dest));
    bpf_probe_read(&ev.src_port, sizeof(ev.src_port), (void *)(&udp->source));
    ev.src_port = SWAP_U16(ev.src_port);
    ev.dest_port = SWAP_U16(ev.dest_port);

    // Get Process data and set pid and comm string
    bpf_get_current_comm(ev.process.comm, sizeof(ev.process.comm));

    // Output data to generator
    push_event(ctx, &ev);
    return 0;
}

SEC("kretprobe/ret_tcp_connect")
int kretprobe__ret_tcp_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    if (ret != 0)
    {
        return 0;
    }

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded); /* squeezing out as much stack as possible */
    if (!loaded)
    {
        return 0;
    }

    // Just to be safe 0 out the structs
    network_event_t ev = {0};

    // Initialize some of the telemetry event
    ev.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 index = (u32)pid_tgid;
    _sock *skpp;

    // if ipv4 do one thing else do the other

    skpp = bpf_map_lookup_elem(&tcp_connect, &index);
    if (skpp == 0)
    {
        return 0;
    }
    bpf_map_delete_elem(&tcp_connect, &index);

    // Deref
    _sock skp = *skpp;
    unsigned char *skp_base = (unsigned char *)skp;
    if (skp_base == NULL)
    {
        return 0;
    }

    // Connect calls are always outbound and this function is for tcp
    ev.direction = outbound;
    ev.protocol_type = IPPROTO_TCP;

    // Get the ip type and then
    read_value(skp_base, CRC_SOCK_COMMON_FAMILY, &ev.ip_type, sizeof(ev.ip_type));
    if (ev.ip_type == AF_INET) {
        read_value(skp_base, CRC_SOCK_COMMON_DADDR, &ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr));
        read_value(skp_base, CRC_SOCK_COMMON_SADDR, &ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr));
    } else if (ev.ip_type == AF_INET6) {
        read_value(skp_base, CRC_SOCK_COMMON_DADDR6, &ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr));
        read_value(skp_base, CRC_SOCK_COMMON_SADDR6, &ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr));
    } else {
        return 0;
    }

    // Get port info
    read_value(skp_base, CRC_SOCK_COMMON_DPORT, &ev.dest_port, sizeof(ev.dest_port));
    read_value(skp_base, CRC_SOCK_COMMON_SPORT, &ev.src_port, sizeof(ev.src_port));
    ev.dest_port = SWAP_U16(ev.dest_port);

    // Get Process data and set pid and comm string
    ev.process.pid = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(ev.process.comm, sizeof(ev.process.comm));

    // Output data to generator
    push_event(ctx, &ev);
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
