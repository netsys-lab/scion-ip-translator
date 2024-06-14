#ifndef SCION_H
#define SCION_H

#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include "scion_types.h"

// 8 bit identifying prefix (currently unassigned ULA range fc00::/8)
// 12 bit ISD
// 20 bit AS
// 24 bit local routing and subnet ID
// 64 bit Host
#define IST_PREFIX ((__u32)(0xFC << (32 - 8)))
#define IST_PREFIX_MASK ((__u32)(0xFF << (32 - 8)))

typedef __u32 scion_addr;

#define SADDR_GET_ISD(k) (((k) >> 20) && 0xFFF)
#define SADDR_GET_AS(k) ((k)&0xFFFFF)
#define SADDR_SET_ISD(k, v) (k) = ((k) & 0xFFFFF) | (((v)&0xFFF) << 20)
#define SADDR_SET_AS(k, v) (k) = ((k) & 0xFFF00000) | ((v)&0xFFFFF)

struct path_map_entry {
	// SCION header information
	// Common header and Address header
	struct scionhdr header;
	// Raw path
	__u32 path[255];
	__u8 path_len;

	// Additional fields required for routing
	// Address of the border router within our AS in network order
	__u8 router_addr[16];
	// I really have no idea how the ports are assigned.
	// The documentation only specifies a port range 30042-30051.
	// https://docs.scion.org/en/latest/manuals/router.html#port-table
	__u16 router_port;
};

inline int scion_prefix_match(struct in6_addr *addr)
{
	return (addr->in6_u.u6_addr8[0] == 0xFC);
}

inline __u32 get_scion_addr(struct in6_addr *addr) {
  return (bpf_ntohl(addr->in6_u.u6_addr32[0]) << 8) | (bpf_ntohl(addr->in6_u.u6_addr32[1]) >> 24);
}

inline scion_addr get_map_key(struct in6_addr *addr)
{
	//scion_addr addr = bpf_ntohl(hdr->daddr.in6_u.u6_addr32[0]) << 8;
	// See include/uapi/linux/ipv6.h
	//addr |= hdr->daddr.in6_u.u6_addr8[4] << 8;
	//addr |= ((hdr->priority & 0xF) << 4) | ((hdr->flow_lbl[0] & 0xF0) >> 4);

	return get_scion_addr(addr);
}

#endif
