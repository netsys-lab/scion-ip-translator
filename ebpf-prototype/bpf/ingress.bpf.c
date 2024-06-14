#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "scion.h"
#include "scion_types.h"


SEC("xdp")
int scion_ingress(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	void *new_start, *scion_end;
  scion_addr src, dst;

	struct ethhdr *eth_hdr = data;
	struct ipv6hdr *ip_hdr = (struct ipv6hdr *)(eth_hdr + 1);
	struct udphdr *udp_hdr = (struct udphdr *)(ip_hdr + 1);
	struct scionhdr *sci_hdr = (struct scionhdr *)(udp_hdr + 1);

	// Packet is too small for Ethernet packet, so not SCION.
	if ((void *)(eth_hdr + 1) > data_end)
		return XDP_PASS;

	// Packet contains no IP header, so not SCION.
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;

	// Packet is too small for IP packet, so not SCION.
	if ((void *)(ip_hdr + 1) > data_end)
		return XDP_PASS;

  if (ip_hdr->nexthdr == NEXTHDR_ICMPV6) {
    return XDP_PASS;
  }

	// Packet is not from a SCION address
	if (!scion_prefix_match(&ip_hdr->daddr)) {
		return XDP_PASS;
	}

	// Packet is too small for UDP packet, so not SCION.
	if ((void *)(udp_hdr + 1) > data_end)
		return XDP_PASS;

	// Packet is too small for SCION packet, so not SCION.
	if ((void *)(sci_hdr + 1) > data_end)
		return XDP_PASS;


	dst = get_scion_addr(&ip_hdr->daddr);
  src = get_scion_addr(&ip_hdr->saddr);

  // Do not translate intra-AS traffic
  //if (dst == src) {
  //  return XDP_PASS;
  //}
  if(ip_hdr->nexthdr == NEXTHDR_TCP) {
    return XDP_PASS;
  }

	// From now on we can be somewhat sure this is a SCION packet.

	// copy host addresses from SCION header to actual IP header
	// so that we can correctly forward to the destination host
	// if deployed in network
	if ((void *)sci_hdr + sizeof(struct scionhdr) + 2 * sizeof(struct in6_addr) > data_end)
		return XDP_PASS;

	__builtin_memcpy(&ip_hdr->daddr, (void *)sci_hdr + sizeof(struct scionhdr), sizeof(struct in6_addr));
	__builtin_memcpy(&ip_hdr->saddr, (void *)sci_hdr + sizeof(struct scionhdr) + sizeof(struct in6_addr), sizeof(struct in6_addr));

	// since we remove part of the payload (from the perspective of the IP header)
	// we have to update some fields, like the L4 type and the actual payload length
	ip_hdr->nexthdr = sci_hdr->next;
	ip_hdr->payload_len = sci_hdr->payload;
	ip_hdr->hop_limit = 0xFF;

	// XXX better check this again for correctness
	ip_hdr->flow_lbl[0] |= (sci_hdr->ver_qos_flow >> 16) & 0xF;
	ip_hdr->flow_lbl[1] = sci_hdr->ver_qos_flow >> 8;
	ip_hdr->flow_lbl[2] = sci_hdr->ver_qos_flow;

	// Calculate end of SCION header so that we can adjust data later.
	scion_end = (void *)sci_hdr + (4 * sci_hdr->len);

	new_start = (void *)scion_end - (sizeof(struct ipv6hdr) + sizeof(struct ethhdr));
	// Move ethernet and IPv6 header to new begin
	if (new_start + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end) {
		return XDP_DROP; // we already borked the packet, so just drop it
	}
	__builtin_memmove(new_start, eth_hdr, sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

	// Grow headroom (aka shrink data) to the new start.
	if (bpf_xdp_adjust_head(ctx, new_start - data) < 0) {
		bpf_printk("Could not adjust packet room");
		return XDP_DROP;
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
