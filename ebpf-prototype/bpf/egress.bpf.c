#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/socket.h>
// For some versions the UDP UAPI does not properly include typedef headers
typedef __u16 __sum16;
typedef __u32 __wsum;
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/udp.h>

#include "common.h"
#include "scion.h"

#define PATH_ENTRIES 4096

/// Map with paths cache
/// Filled by the userspace daemon with preferred paths
/// for given destination ISD-AS addresses.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, scion_addr);
	__type(value, struct path_map_entry);
	__uint(max_entries, PATH_ENTRIES);
} path_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * sizeof(scion_addr));
} path_req SEC(".maps");

/// Serialize SCION common and address header
///
/// buf: target buffer
/// hdr: prefilled header from userspace map
/// iph: original IPv6 header
///
/// Returns number of written bytes
///
/// NOTE: this does not write the host addresses yet!
static inline __u32 write_scionhdr(void *buf, struct scionhdr *hdr, struct ipv6hdr *iph)
{
	struct scionhdr *new_hdr = (struct scionhdr *)buf;
	__builtin_memcpy(new_hdr, hdr, sizeof(struct scionhdr));

	// 4b version field is always zero
	SC_SET_VER(new_hdr, 0); // should be set by userspace
	// 8b copy traffic class from IP header
	// See linux/ipv6.h to see why this is so ugly
	SC_SET_QOS(new_hdr, ((__u32)((iph->priority << 4) | (iph->flow_lbl[0] >> 4))));
	// 20b copy flow label from IP header
	SC_SET_FLOW(new_hdr, ((((__u32)iph->flow_lbl[0] & 0xF) << 16) | ((__u32)iph->flow_lbl[1] << 8) | (__u32)iph->flow_lbl[2]));

	// 8b copy nexthdr from IP header
	new_hdr->next = iph->nexthdr;
	// 16b copy payload length from IP header
	new_hdr->payload = iph->payload_len;

	return sizeof(struct scionhdr);
}

/// Serialize the host addresses
///
/// buf: target buffer
/// daddr: destination IP address
/// saddr: source IP address
///
/// Returns number of written bytes
static inline __u32 write_host_addr(void *buf, struct in6_addr *daddr, struct in6_addr *saddr)
{
	// Not sure if this works well in all cases because in6_addr may include more
	// than just the address itself. Besides the byte order might not be right
	// despite coming from the net stack?
	__builtin_memcpy(buf, daddr, sizeof(*daddr));
	__builtin_memcpy(buf + sizeof(*daddr), saddr, sizeof(*saddr));

	return 2 * sizeof(struct in6_addr);
}

static inline int adjust_eth(struct __sk_buff *ctx, struct ethhdr *eth, struct ipv6hdr *iph) {
//  struct bpf_fib_lookup fib_params;
//  struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
//  struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;
//  long ret;
//
//  __builtin_memset(&fib_params, 0, sizeof(fib_params));
//  fib_params.family	= AF_INET6;
//	fib_params.tot_len	= bpf_ntohs(iph->payload_len);
//  *src = iph->saddr;
//  *dst = iph->daddr;
//
//  ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_OUTPUT);
//
//  if (ret != BPF_FIB_LKUP_RET_SUCCESS) {
//    bpf_printk("FIB lookup unsuccessful: %d", ret);
//    return TC_ACT_SHOT;
//  }
//
//  __builtin_memcpy(eth->h_source, fib_params.smac, 6);
//  __builtin_memcpy(eth->h_dest, fib_params.dmac, 6);

//   __u8 src[12] = {};
//   __u8 dst[12] = {};

//   __builtin_memcpy(eth->h_source, src, 6);
//   __builtin_memcpy(eth->h_dest, dst, 6);

  return TC_ACT_OK;
}

/// eBPF program to rewrite IPv6 packet to SCION packet
SEC("tc/egress")
int scion_egress(struct __sk_buff *ctx)
{
	scion_addr dst, src;
  __u16 src_port;
	__u32 netdev_mtu_len = 0;
	__u32 new_hdrs_size, scion_header_len;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *sci_end;

	struct ethhdr *eth_hdr = data;
	struct ipv6hdr *ip6_hdr = (struct ipv6hdr *)(eth_hdr + 1);
	struct udphdr *udp_hdr = (struct udphdr *)(ip6_hdr + 1);
	struct scionhdr *sci_hdr = (struct scionhdr *)(udp_hdr + 1);

	struct path_map_entry *path;

	// Packet is too small for Ethernet, just forward.
	if ((void *)(eth_hdr + 1) > data_end)
		return TC_ACT_OK;

	// Packet is not IPv6, just forward.
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	// Packet is too small to hold an IP packet, just forward.
	if ((void *)(ip6_hdr + 1) > data_end)
		return TC_ACT_OK;

  if (ip6_hdr->nexthdr == NEXTHDR_ICMPV6) {
    return TC_ACT_OK;
  }

  //bpf_printk("check prefix");
	// IP destination address is not in SCION range, just forward.
	if (!scion_prefix_match(&ip6_hdr->daddr)) {
		return TC_ACT_OK;
  }


	dst = get_scion_addr(&ip6_hdr->daddr);
  src = get_scion_addr(&ip6_hdr->saddr);

  //bpf_printk("check intra as");
  // Do not translate intra-AS traffic
  if (dst == src) {
    return TC_ACT_OK;
  }

	// Packet is too small to hold a UDP packet, just forward.
	if ((void *)(udp_hdr + 1) > data_end)
		return TC_ACT_OK;

  src_port = udp_hdr->source;

	// From this point we can be somewhat sure this packet is addressed
	// to a SCION AS and we can start the rewrite process.

	// Packet is an ICMP packet (e.g. ping), so we rewrite it to SCMP
	if (ip6_hdr->nexthdr == NEXTHDR_ICMPV6) {
    // TODO tail call to SCMP translation
	} else {
    // TODO tail call to regular IPv6 translation
  }

  dst = get_map_key(&ip6_hdr->daddr);

  //bpf_printk("lookup path");
	// Lookup path information for given SCION ISD-AS.
	path = bpf_map_lookup_elem(&path_map, &dst);
	// Since we checked earlier for the prefix a miss means
	// that there is no path cached.
	// As a result the userspace daemon has to update the cache.
	// However, since bpf programs run atomically we cannot wait
	// and instead have to either circulate the packet through the netwock stack
	// or send the packet to userspace and re-send it once the cache is filled.
	if (!path) {
		// TODO in order to implement the recirculation
		// another map counting some kind of TTL might be sensible
		bpf_ringbuf_output(&path_req, &dst, sizeof(dst), 0);
    // TODO do not use recirculation but user space buffering
		//return bpf_redirect(ctx->ifindex, 0);
    return TC_ACT_SHOT;
	}
  // TODO implement way to check wether no path available or not cached

  //bpf_printk("Path found");

	scion_header_len = 4 * path->header.len;

	// We insert a UDP header and the SCION headers
	new_hdrs_size = sizeof(struct udphdr) + scion_header_len;

	// Check if we can fit the additional header into the packet
	if (bpf_check_mtu(ctx, 0, &netdev_mtu_len, -new_hdrs_size, 0)) {
		bpf_printk("MTU check failed");
		return TC_ACT_SHOT;
	}
	// Adjust sk_buffer space so that we can include the SCION header.
	if (bpf_skb_adjust_room(ctx, new_hdrs_size, BPF_ADJ_ROOM_NET, 0) < 0) {
		bpf_printk("could not increase packet data size");
		return TC_ACT_SHOT;
	}

  //bpf_printk("Packet size adjusted");

	// Adjust new pointer offsets.
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth_hdr = (struct ethhdr *)data;
	ip6_hdr = (struct ipv6hdr *)(eth_hdr + 1);
	udp_hdr = (struct udphdr *)(ip6_hdr + 1);
	sci_hdr = (struct scionhdr *)(udp_hdr + 1);

	if ((void *)sci_hdr + scion_header_len > data_end) {
		bpf_printk("packet is too small for new headers");
		return TC_ACT_SHOT;
	}

	if (((void *)(eth_hdr + 1) > data_end))
		return TC_ACT_SHOT;
	if (((void *)(ip6_hdr + 1) > data_end))
		return TC_ACT_SHOT;

	if (((void *)(sci_hdr + 1) > data_end))
		return TC_ACT_SHOT;

  //bpf_printk("Copy path");

	// Set underlay UDP header
	udp_hdr->dest = bpf_htons(path->router_port);
	// We use the port of the dispatcher
	udp_hdr->source = bpf_htons(src_port);

	// Write SCION header to buffer
	// We add the size of the headers to be inserted in order to retrieve information from the orignal header
	sci_end = sci_hdr;
	sci_end += write_scionhdr(sci_hdr, &path->header, ip6_hdr);

	if (((void *)sci_end + 2 * sizeof(struct in6_addr) > data_end))
		return TC_ACT_SHOT;
	sci_end += write_host_addr(sci_end, &ip6_hdr->daddr, &ip6_hdr->saddr);

	// This should copy the path from the map to the packet.
	__u32 *to = (__u32 *)sci_end;
	__u32 *from = (__u32 *)path->path;

	if ((to + path->path_len) > (__u32 *)data_end)
		TC_ACT_SHOT;

	// TODO its quite unfortunate we have to do this expensive check every iteration
	// but the check above is not satisfying the verifier
	for (__u8 i = 0; i < path->path_len && (void *)(to + i + 1) < data_end; i++)
		to[i] = from[i];

	//pathcpy(ctx, sci_end, path->path, path->path_len);
	sci_end += scion_header_len;

	// Transform IP header for intra-AS forwarding to the border router.
	__builtin_memcpy(ip6_hdr->daddr.in6_u.u6_addr8, path->router_addr, 16);
	ip6_hdr->nexthdr = NEXTHDR_UDP;

	// The required fields are written later, which is why we have to adjust the fields now.
	ip6_hdr->payload_len = bpf_htons((__u16)sizeof(struct udphdr) + (4 * (__u16)sci_hdr->len) + bpf_ntohs(sci_hdr->payload));
	udp_hdr->len = ip6_hdr->payload_len;

	// Adjust UDP checksum
  // NOTE left to hw offload


  //bpf_printk("Finished packet rewriting");
	return adjust_eth(ctx, eth_hdr, ip6_hdr);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
