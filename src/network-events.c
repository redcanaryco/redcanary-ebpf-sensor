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
    .max_entries = MAX_TELEMETRY_STACK_ENTRIES * 64,
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
    telemetry_event_t ev;
    __builtin_memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    if (sk_base == NULL)
    {
        return 0;
    }

    ev.u.network_info.direction = inbound;
    ev.u.network_info.protocol_type = IPPROTO_TCP;

    u64 loaded = CRC_LOADED;
    loaded = (u64)bpf_map_lookup_elem(&offsets, &loaded);
    int ret = read_value(sk_base, CRC_SOCK_COMMON_FAMILY, &ev.u.network_info.ip_type, sizeof(ev.u.network_info.ip_type));
    if (ret == -1)
    {
        return 0;
    }

    if (ev.u.network_info.ip_type == AF_INET && loaded)
    {
        // The dest and src are intentionally backwards
        read_value(sk_base, CRC_SOCK_COMMON_SADDR, &ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr));
        read_value(sk_base, CRC_SOCK_COMMON_DADDR, &ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
        read_value(sk_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
        ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    }
    else if (ev.u.network_info.ip_type == AF_INET6 && loaded)
    {
        // The dest and src are intentionally backwards
        read_value(sk_base, CRC_SOCK_COMMON_SADDR6, &ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr));
        read_value(sk_base, CRC_SOCK_COMMON_DADDR6, &ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr));
        read_value(sk_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
        read_value(sk_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
        ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    }

    // Get Process data and set pid and comm string
    ev.u.network_info.process.pid = (u32)bpf_get_current_pid_tgid();
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &network_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));

    return 0;
}

// This handles both IPv4 and IPv6 udp packets
SEC("kretprobe/ret___skb_recv_udp")
int kretprobe__ret___skb_recv_udp(struct pt_regs *ctx)
{
    //unsigned char version = 0;
    telemetry_event_t ev;
    __builtin_memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.protocol_type = IPPROTO_UDP;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    _skbuff skb = (_skbuff)PT_REGS_RC(ctx);
    unsigned char *skbuff_base = (unsigned char *)skb;

    if (skbuff_base == NULL)
    {
        bpf_printk("In __skb_recv_udp: skbuff_base\n");
        return 0;
    }

    ev.u.network_info.direction = inbound;
    ev.u.network_info.protocol_type = IPPROTO_UDP;

    // Get current pid
    ev.u.network_info.process.pid = (u32)bpf_get_current_pid_tgid();

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
        bpf_printk("In __skb_recv_udp: read skbuff->head\n");
        return 0;
    }

    ret = read_value(skbuff_base, CRC_SKBUFF_MAC_HDR, &mac_header, sizeof(mac_header));
    if (ret == -1)
    {
        bpf_printk("In __skb_recv_udp: read transport header\n");
        return 0;
    }

    ret = read_value(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header));
    if (ret == -1)
    {
        bpf_printk("In __skb_recv_udp: read transport header\n");
        return 0;
    }

    ret = read_value(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header));
    if (ret == -1)
    {
        bpf_printk("In __skb_recv_udp: network header\n");
        return 0;
    }

    ret = read_value(skbuff_base, CRC_SKBUFF_PROTO, &proto, sizeof(proto));
    if (ret == -1)
    {
        bpf_printk("In __skb_recv_udp: skbuff->proto\n");
        return 0;
    }

    u64 eth_proto_offset = CRC_SKBUFF_PROTO;
    eth_proto_offset = (u64)bpf_map_lookup_elem(&offsets, &eth_proto_offset);

    struct ethhdr *eth = (struct ethhdr *)(skb_head + mac_header);
    struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
    struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);
    //bpf_probe_read(&version, sizeof(version), (void *)(ip));
    //version = ((version & 0xf0) >> 4); // Get the upper 4 bits
    bpf_probe_read(&proto, sizeof(proto), (void *)(&eth->h_proto));
    bpf_printk("eth->h_proto: 0x%x\n", proto);
    if (proto == 0x8)
    {
        bpf_printk("In __skb_recv_udp: In ipv4\n");
        ev.u.network_info.ip_type = AF_INET;
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ip->protocol));
        proto = proto & 0xff;
        bpf_printk("ipv4->protocol: 0x%x\n", proto);

        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr), (void *)(&ip->daddr));
            bpf_probe_read(&ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr), (void *)(&ip->saddr));
        }
        else
        {
            // If it is not udp we don't care
            bpf_printk("In __skb_recv_udp: Unknown protocol\n");
            return 0;
        }
    }
    else if (proto == 0xdd86)
    {
        bpf_printk("In __skb_recv_udp: In ipv6\n");
        ev.u.network_info.ip_type = AF_INET6;
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(skb_head + network_header);
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ipv6->nexthdr));
        proto = proto & 0xff;
        bpf_printk("ipv6->nexthdr: 0x%x\n", proto);
        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr), (void *)(&ipv6->daddr));
            bpf_probe_read(&ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr), (void *)(&ipv6->saddr));
        }
        else
        {
            // If it is not udp we don't care
            bpf_printk("In __skb_recv_udp: Unknown protocol\n");
            return 0;
        }
    }
    else
    {
        // We should not ever get here
        //bpf_printk("Couldn't get ip version: %d\n", version);
        return 0;
    }
    bpf_probe_read(&ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port), (void *)(&udp->dest));
    bpf_probe_read(&ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port), (void *)(&udp->source));
    ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port);

    // Get Process data and set pid and comm string

    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &network_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
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
    telemetry_event_t ev;
    __builtin_memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.protocol_type = IPPROTO_UDP;
    ev.u.network_info.direction = outbound;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();
    ev.u.network_info.process.pid = index;

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
        ev.u.network_info.ip_type = AF_INET;
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ip->protocol));
        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr), (void *)(&ip->daddr));
            bpf_probe_read(&ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr), (void *)(&ip->saddr));
        }
        else
        {
            // If it is not udp we don't care
            return 0;
        }
    }
    else if (version == 6)
    {
        ev.u.network_info.ip_type = AF_INET6;
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(skb_head + network_header);
        bpf_probe_read(&proto, sizeof(proto), (void *)(&ipv6->nexthdr));
        if (proto == IPPROTO_UDP)
        {
            bpf_probe_read(&ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr), (void *)(&ipv6->daddr));
            bpf_probe_read(&ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr), (void *)(&ipv6->saddr));
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
    bpf_probe_read(&ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port), (void *)(&udp->dest));
    bpf_probe_read(&ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port), (void *)(&udp->source));
    ev.u.network_info.src_port = SWAP_U16(ev.u.network_info.src_port);
    ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port);

    // Get Process data and set pid and comm string
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &network_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
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
    telemetry_event_t ev;
    __builtin_memset(&ev, 0, sizeof(ev));

    // Initialize some of the telemetry event
    ev.id = bpf_get_prandom_u32();
    ev.done = 0;
    ev.telemetry_type = TE_NETWORK;
    ev.u.network_info.mono_ns = bpf_ktime_get_ns();

    // Get current pid
    u32 index = (u32)bpf_get_current_pid_tgid();
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
    ev.u.network_info.direction = outbound;
    ev.u.network_info.protocol_type = IPPROTO_TCP;

    // Get the ip type and then
    read_value(skp_base, CRC_SOCK_COMMON_FAMILY, &ev.u.network_info.ip_type, sizeof(ev.u.network_info.ip_type));
    if (ev.u.network_info.ip_type == AF_INET)
    {
        read_value(skp_base, CRC_SOCK_COMMON_DADDR, &ev.u.network_info.protos.ipv4.dest_addr, sizeof(ev.u.network_info.protos.ipv4.dest_addr));
        read_value(skp_base, CRC_SOCK_COMMON_SADDR, &ev.u.network_info.protos.ipv4.src_addr, sizeof(ev.u.network_info.protos.ipv4.src_addr));
    }
    else
    {
        read_value(skp_base, CRC_SOCK_COMMON_DADDR6, &ev.u.network_info.protos.ipv6.dest_addr, sizeof(ev.u.network_info.protos.ipv6.dest_addr));
        read_value(skp_base, CRC_SOCK_COMMON_SADDR6, &ev.u.network_info.protos.ipv6.src_addr, sizeof(ev.u.network_info.protos.ipv6.src_addr));
    }

    // Get port info
    read_value(skp_base, CRC_SOCK_COMMON_DPORT, &ev.u.network_info.dest_port, sizeof(ev.u.network_info.dest_port));
    read_value(skp_base, CRC_SOCK_COMMON_SPORT, &ev.u.network_info.src_port, sizeof(ev.u.network_info.src_port));
    ev.u.network_info.dest_port = SWAP_U16(ev.u.network_info.dest_port);

    // Get Process data and set pid and comm string
    ev.u.network_info.process.pid = index;
    bpf_get_current_comm(ev.u.network_info.process.comm, sizeof(ev.u.network_info.process.comm));

    // Output data to generator
    bpf_perf_event_output(ctx, &network_events, bpf_get_smp_processor_id(), &ev, sizeof(ev));
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
