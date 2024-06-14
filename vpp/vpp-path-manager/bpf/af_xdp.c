#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <stdbool.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#ifdef DEBUG
#define printf(fmt, ...) do { \
const char _fmt[] = fmt; \
bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
} while (0)
#else
#define printf(...)
#endif

#define DEFAULT_QUEUE_IDS 64
#define VLAN_MAX_DEPTH 4
#define IPV6_MAX_ESTENSIONS 6
#define MIN_SCION_HDR_SIZE (8 + 12 + 48)
#define MIN_PACKET_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MIN_SCION_HDR_SIZE)

#define proto_is_vlan(proto) (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))

struct filter_config
{
    __u32 ipv4;
    struct in6_addr ipv6;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct filter_config));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} scion_ip SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, DEFAULT_QUEUE_IDS);
} xsks_map SEC(".maps");

struct vlan_hdr
{
    __be16 tci;
    __be16 proto;
};

__attribute__((__always_inline__))
inline bool comp_ipv6(struct in6_addr* a, struct in6_addr* b)
{
    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        if (a->in6_u.u6_addr32[i] != b->in6_u.u6_addr32[i]) {
            return false;
        }
    }
    return true;
}

__attribute__((__always_inline__))
inline __be16 parse_ethernet(void** data, void* data_end)
{
    if (*data + sizeof(struct ethhdr) > data_end) return 0;
    struct ethhdr* eth = *data;

    *data = eth + 1;
    struct vlan_hdr* tag = *data;
    __be16 proto = eth->h_proto;
    #pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH && proto_is_vlan(proto); ++i) {
        if ((void*)(tag + 1) > data_end) break;
        proto = tag->proto;
        ++tag;
    }
    *data = tag;

    return proto;
}

__attribute__((__always_inline__))
inline bool parse_ipv4(void** data, void* data_end, struct iphdr** hdr)
{
    if (*data + sizeof(struct iphdr) > data_end) return false;
    struct iphdr* ip = *data;

    __u32 hdrsize = 4 * ip->ihl;
    if (*data + hdrsize > data_end) return false;
    *data += hdrsize;

    *hdr = ip;
    return true;
}

__attribute__((__always_inline__))
inline bool parse_ipv6(void** data, void* data_end, struct ipv6hdr** hdr, __u8* next)
{
    if (*data + sizeof(struct ipv6hdr) > data_end) return false;
    struct ipv6hdr* ip = *data;

    __u8 nh = ip->nexthdr;
    *data = ip + 1;

    for (int i = 0; i < IPV6_MAX_ESTENSIONS; ++i) {
        struct ipv6_opt_hdr* opt = *data;
        if ((void*)(opt + 1) > data_end) return false;

        switch (nh) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_DSTOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_MH:
            nh = opt->nexthdr;
            *data = *data + (opt->hdrlen + 1) * 8;
            break;
        case IPPROTO_AH:
            nh = opt->nexthdr;
            *data = *data + (opt->hdrlen + 1) * 4;
            break;
        case IPPROTO_FRAGMENT:
            nh = opt->nexthdr;
            *data = *data + 8;
            break;
        default:
            *hdr = ip;
            *next = nh;
            return true;
        }
    }
    return false;
}

SEC("prog")
int scion_filter(struct xdp_md* ctx)
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    printf("packet in (%d bytes)\n", data_end - data);

    if ((unsigned long)(data_end - data) < MIN_PACKET_SIZE) {
        printf("packet too small\n");
        return XDP_PASS;
    }

    __u32 key = 0;
    struct filter_config* filter = bpf_map_lookup_elem(&scion_ip, &key);
    if (!filter) return XDP_PASS;

    __be16 proto = parse_ethernet(&data, data_end);
    printf("proto = %x\n", (int)proto);
    if (proto == bpf_ntohs(ETH_P_IP)) {
        printf("packet is IPv4\n");
        struct iphdr* ip = NULL;
        if (!parse_ipv4(&data, data_end, &ip)) return XDP_PASS;

        if (ip->daddr != filter->ipv4) {
            printf("destination address does not match\n");
            return XDP_PASS;
        }

        if (ip->protocol != IPPROTO_ICMP && ip->protocol != IPPROTO_UDP) {
            printf("l4 type dpes not match (%d)\n", ip->protocol);
            return XDP_PASS;
        }

    } else if (proto == bpf_ntohs(ETH_P_IPV6)) {
        printf("packet is IPv6\n");
        struct ipv6hdr* ip = NULL;
        __u8 next_hdr = 0;
        if (!parse_ipv6(&data, data_end, &ip, &next_hdr)) return XDP_PASS;

        if (!comp_ipv6(&ip->daddr, &filter->ipv6)) {
            printf("destination address does not match\n");
            return XDP_PASS;
        }

        if (next_hdr != IPPROTO_ICMP && next_hdr != IPPROTO_UDP) {
            printf("l4 type dpes not match (%d)\n", next_hdr);
            return XDP_PASS;
        }

    } else {
        printf("not IP\n");
        return XDP_PASS;
    }

    printf("redirecting (queue %d)\n", ctx->rx_queue_index);
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}
