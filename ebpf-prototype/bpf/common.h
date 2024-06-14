#pragma once

#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/types.h>

// Not exposed in the UAPI, so we have to declare it manually
#define NEXTHDR_TCP 6
#define NEXTHDR_UDP 17
#define NEXTHDR_ICMPV6 58
// https://docs.scion.org/en/latest/protocols/scmp.html
#define NEXTHDR_SCMP 202

// https://docs.scion.org/en/latest/manuals/dispatcher.html#port-table
#define SCION_DISPATCHER_PORT 30041

#define AF_INET6 10

#define BPF_PRINT_DEBUG(str) do { bpf_printk((str)); } while(0)

static inline __u16 udp_csum(struct in6_addr *saddr, struct in6_addr *daddr, __u8 proto, __u16 udp_len) {
  __u32 res = 0;

  // source address
  res += (((__u16)saddr->in6_u.u6_addr8[0] << 8) | saddr->in6_u.u6_addr8[1]);
  res += (((__u16)saddr->in6_u.u6_addr8[2] << 8) | saddr->in6_u.u6_addr8[3]);
  res += (((__u16)saddr->in6_u.u6_addr8[4] << 8) | saddr->in6_u.u6_addr8[5]);
  res += (((__u16)saddr->in6_u.u6_addr8[6] << 8) | saddr->in6_u.u6_addr8[7]);
  res += (((__u16)saddr->in6_u.u6_addr8[8] << 8) | saddr->in6_u.u6_addr8[9]);
  res += (((__u16)saddr->in6_u.u6_addr8[10] << 8) | saddr->in6_u.u6_addr8[11]);
  res += (((__u16)saddr->in6_u.u6_addr8[12] << 8) | saddr->in6_u.u6_addr8[13]);
  res += (((__u16)saddr->in6_u.u6_addr8[14] << 8) | saddr->in6_u.u6_addr8[15]);

  // destination address
  res += (((__u16)daddr->in6_u.u6_addr8[0] << 8) | daddr->in6_u.u6_addr8[1]);
  res += (((__u16)daddr->in6_u.u6_addr8[2] << 8) | daddr->in6_u.u6_addr8[3]);
  res += (((__u16)daddr->in6_u.u6_addr8[4] << 8) | daddr->in6_u.u6_addr8[5]);
  res += (((__u16)daddr->in6_u.u6_addr8[6] << 8) | daddr->in6_u.u6_addr8[7]);
  res += (((__u16)daddr->in6_u.u6_addr8[8] << 8) | daddr->in6_u.u6_addr8[9]);
  res += (((__u16)daddr->in6_u.u6_addr8[10] << 8) | daddr->in6_u.u6_addr8[11]);
  res += (((__u16)daddr->in6_u.u6_addr8[12] << 8) | daddr->in6_u.u6_addr8[13]);
  res += (((__u16)daddr->in6_u.u6_addr8[14] << 8) | daddr->in6_u.u6_addr8[15]);

  res += proto;

  res += udp_len;

  // carry addition
  res = (res & 0xFF00) + (res & 0xFF);

  // one's complement
  return ~(__u16)res;
}
