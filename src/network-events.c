#include "vmlinux.h"

#include "common/common.h"
#include "common/offsets.h"
#include "common/types.h"

// Just doing a simple 16-bit byte swap
#define SWAP_U16(x) (((x) >> 8) | ((x) << 8))

struct bpf_map_def SEC("maps/tcp_connect") tcp_connect_data = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(void *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udp_outgoing_map") udp_outgoing_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(void *),
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

static __always_inline network_event_t init_message(u64 pid_tgid, u16 protocol_type, enum direction_t direction) {
    network_event_t ev = {0};
    ev.mono_ns = bpf_ktime_get_ns();
    ev.direction = direction;
    ev.protocol_type = protocol_type;
    ev.process.pid = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(ev.process.comm, sizeof(ev.process.comm));

    return ev;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, void *sk)
{
    u32 index = (u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_connect_data, &index, &sk, BPF_ANY);
    return 0;
}

SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out, void *net, void *sk, void *skb)
{
    u32 index = (u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_outgoing_map, &index, &skb, BPF_ANY);
    return 0;
}

SEC("kprobe/udp_outgoing")
int BPF_KPROBE(udp_outgoing, void *skb)
{
    u32 index = (u32)bpf_get_current_pid_tgid();
    bpf_map_update_elem(&udp_outgoing_map, &index, &skb, BPF_ANY);
    return 0;
}

SEC("kretprobe/ret_inet_csk_accept")
int BPF_KRETPROBE(ret_inet_csk_accept, void *sk_base)
{
    if (sk_base == NULL) return 0;
    if (!offset_loaded()) return 0;

    // Initialize new message
    network_event_t ev = init_message(bpf_get_current_pid_tgid(), IPPROTO_TCP, inbound);

    if (read_field(sk_base, CRC_SOCK_COMMON_FAMILY, &ev.ip_type, sizeof(ev.ip_type)) < 0) return 0;

    // The dest and src are intentionally backwards
    switch (ev.ip_type) {
    case AF_INET:
        read_field(sk_base, CRC_SOCK_COMMON_SADDR, &ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr));
        read_field(sk_base, CRC_SOCK_COMMON_DADDR, &ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr));
        break;
    case AF_INET6:
        read_field(sk_base, CRC_SOCK_COMMON_SADDR6, &ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr));
        read_field(sk_base, CRC_SOCK_COMMON_DADDR6, &ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr));
        break;
    default:
        return 0;
    }

    read_field(sk_base, CRC_SOCK_COMMON_SPORT, &ev.dest_port, sizeof(ev.dest_port));
    read_field(sk_base, CRC_SOCK_COMMON_DPORT, &ev.src_port, sizeof(ev.src_port));
    ev.src_port = SWAP_U16(ev.src_port);

    // Output data to generator
    push_event(ctx, &ev);

    return 0;
}

// This handles both IPv4 and IPv6 udp packets
SEC("kretprobe/ret___skb_recv_udp")
int BPF_KRETPROBE(ret___skb_recv_udp, void *skbuff_base)
{
    if (skbuff_base == NULL) return 0;
    if (!offset_loaded()) return 0;

    // Initialize new message
    network_event_t ev = init_message(bpf_get_current_pid_tgid(), IPPROTO_UDP, inbound);

    unsigned char *skb_head = read_field_ptr(skbuff_base, CRC_SKBUFF_HEAD);
    if (skb_head == NULL) return 0;

    unsigned short mac_header = 0;
    if (read_field(skbuff_base, CRC_SKBUFF_MAC_HDR, &mac_header, sizeof(mac_header)) < 0) return 0;
    struct ethhdr *eth = (struct ethhdr *)(skb_head + mac_header);

    unsigned short network_header = 0;
    if (read_field(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header)) < 0) return 0;

    __be16 proto = 0;
    if (bpf_probe_read_kernel(&proto, sizeof(proto), (void *)(&eth->h_proto)) < 0) return 0;

    switch (proto) {
    case 0x8: {
        struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
        bpf_probe_read_kernel(&proto, sizeof(proto), (void *)(&ip->protocol));

        // If it is not udp we don't care
        if ((proto & 0xff) != IPPROTO_UDP) return 0;

        ev.ip_type = AF_INET;
        bpf_probe_read_kernel(&ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr), (void *)(&ip->daddr));
        bpf_probe_read_kernel(&ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr), (void *)(&ip->saddr));
        break;
    }
    case 0xdd86: {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(skb_head + network_header);
        bpf_probe_read_kernel(&proto, sizeof(proto), (void *)(&ipv6->nexthdr));

        // If it is not udp we don't care
        if ((proto & 0xff) != IPPROTO_UDP) return 0;

        ev.ip_type = AF_INET6;
        bpf_probe_read_kernel(&ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr), (void *)(&ipv6->daddr));
        bpf_probe_read_kernel(&ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr), (void *)(&ipv6->saddr));
        break;
    }
    default:
        return 0;
    }

    unsigned short transport_header = 0;
    if (read_field(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header)) < 0) return 0;
    struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);

    bpf_probe_read_kernel(&ev.dest_port, sizeof(ev.dest_port), (void *)(&udp->dest));
    bpf_probe_read_kernel(&ev.src_port, sizeof(ev.src_port), (void *)(&udp->source));
    ev.src_port = SWAP_U16(ev.src_port);
    ev.dest_port = SWAP_U16(ev.dest_port);

    // Output data to generator
    push_event(ctx, &ev);
    return 0;
}

// This handles outgoing udp packets
SEC("kretprobe/ret_udp_outgoing")
int BPF_KRETPROBE(ret_udp_outgoing, int ret)
{
    if (ret < 0) return 0;
    if (!offset_loaded()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Initialize new message
    network_event_t ev = init_message(pid_tgid, IPPROTO_UDP, outbound);

    // Lookup the corresponding sk_buff* that we saved during udp_outgoing or ip_local_out
    u32 index = (u32)pid_tgid;
    void **skpp = (void **)bpf_map_lookup_elem(&udp_outgoing_map, &index);
    if (skpp == NULL) return 0;

    // deref and only AFTER remove from map
    void *skbuff_base = *skpp;
    bpf_map_delete_elem(&udp_outgoing_map, &index);
    if (skbuff_base == NULL) return 0;

    unsigned char *skb_head = read_field_ptr(skbuff_base, CRC_SKBUFF_HEAD);
    if (skb_head == NULL) return 0;

    unsigned short transport_header = 0;
    if (read_field(skbuff_base, CRC_TRANSPORT_HDR, &transport_header, sizeof(transport_header)) < 0) return 0;

    unsigned short network_header = 0;
    if (read_field(skbuff_base, CRC_NETWORK_HDR, &network_header, sizeof(network_header)) < 0) return 0;

    struct iphdr *ip = (struct iphdr *)(skb_head + network_header);
    struct udphdr *udp = (struct udphdr *)(skb_head + transport_header);

    unsigned char version = 0;
    bpf_probe_read_kernel(&version, sizeof(version), (void *)(ip));

    switch ((version & 0xf0) >> 4) { // Get the upper 4 bits
    case 4: {
        unsigned char proto = 0;
        bpf_probe_read_kernel(&proto, sizeof(proto), (void *)(&ip->protocol));
        // If it is not udp we don't care
        if (proto != IPPROTO_UDP) return 0;

        ev.ip_type = AF_INET;
        bpf_probe_read_kernel(&ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr), (void *)(&ip->daddr));
        bpf_probe_read_kernel(&ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr), (void *)(&ip->saddr));
        break;
    }
    case 6: {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(ip);
        unsigned char proto = 0;
        bpf_probe_read_kernel(&proto, sizeof(proto), (void *)(&ipv6->nexthdr));
        // If it is not udp we don't care
        if (proto != IPPROTO_UDP) return 0;

        ev.ip_type = AF_INET6;
        bpf_probe_read_kernel(&ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr), (void *)(&ipv6->daddr));
        bpf_probe_read_kernel(&ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr), (void *)(&ipv6->saddr));
        break;
    }
    default:
        return 0;
    }

    bpf_probe_read_kernel(&ev.dest_port, sizeof(ev.dest_port), (void *)(&udp->dest));
    bpf_probe_read_kernel(&ev.src_port, sizeof(ev.src_port), (void *)(&udp->source));
    ev.src_port = SWAP_U16(ev.src_port);
    ev.dest_port = SWAP_U16(ev.dest_port);

    // Output data to generator
    push_event(ctx, &ev);
    return 0;
}

SEC("kretprobe/ret_tcp_connect")
int BPF_KRETPROBE(ret_tcp_connect, int ret)
{
    if (ret != 0) return 0;
    if (!offset_loaded()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Initialize new message
    network_event_t ev = init_message(pid_tgid, IPPROTO_TCP, outbound);

    // Lookup the corresponding _sock* that we saved during tcp_connect
    u32 index = (u32)pid_tgid;
    void **skpp = (void **)bpf_map_lookup_elem(&tcp_connect_data, &index);
    if (skpp == NULL) return 0;

    // deref and only AFTER remove from map
    void *skp_base = *skpp;
    bpf_map_delete_elem(&tcp_connect_data, &index);
    if (skp_base == NULL) return 0;

    // Get the ip type and then
    if (read_field(skp_base, CRC_SOCK_COMMON_FAMILY, &ev.ip_type, sizeof(ev.ip_type)) < 0) return 0;
    if (ev.ip_type == AF_INET) {
        read_field(skp_base, CRC_SOCK_COMMON_DADDR, &ev.protos.ipv4.dest_addr, sizeof(ev.protos.ipv4.dest_addr));
        read_field(skp_base, CRC_SOCK_COMMON_SADDR, &ev.protos.ipv4.src_addr, sizeof(ev.protos.ipv4.src_addr));
    } else if (ev.ip_type == AF_INET6) {
        read_field(skp_base, CRC_SOCK_COMMON_DADDR6, &ev.protos.ipv6.dest_addr, sizeof(ev.protos.ipv6.dest_addr));
        read_field(skp_base, CRC_SOCK_COMMON_SADDR6, &ev.protos.ipv6.src_addr, sizeof(ev.protos.ipv6.src_addr));
    } else {
        return 0;
    }

    // Get port info
    read_field(skp_base, CRC_SOCK_COMMON_DPORT, &ev.dest_port, sizeof(ev.dest_port));
    read_field(skp_base, CRC_SOCK_COMMON_SPORT, &ev.src_port, sizeof(ev.src_port));
    ev.dest_port = SWAP_U16(ev.dest_port);

    // Output data to generator
    push_event(ctx, &ev);
    return 0;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = 0xFFFFFFFE;
