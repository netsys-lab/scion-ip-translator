// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef SCION_H_GUARD
#define SCION_H_GUARD

#include <bpf/bpf_endian.h>
#include <linux/types.h>

/* SCION common */

#define SC_PROTO_TCP 6
#define SC_PROTO_UDP 17
#define SC_PROTO_HBH 200
#define SC_PROTO_E2E_EXT 201
#define SC_PROTO_SCMP 202
#define SC_PROTO_BFD 203
#define SC_PROTO_EXP1 253
#define SC_PROTO_EXP2 254

#define SC_PATH_TYPE_EMPTY 0
#define SC_PATH_TYPE_SCION 1
#define SC_PATH_TYPE_ONE_HOP 2
#define SC_PATH_TYPE_EPIC 3
#define SC_PATH_TYPE_COLIBRI 4

#define SC_ADDR_TYPE_IP 0

#define SC_GET_VER(sc) (ntohl((sc)->ver_qos_flow) >> 28)
#define SC_GET_QOS(sc) ((ntohl((sc)->ver_qos_flow) >> 20) & 0xff)
#define SC_GET_FLOW(sc) (ntohl((sc)->ver_qos_flow) & ((1 << 20ul) - 1))
#define SC_GET_DT(sc) (((sc)->haddr >> 6) & 0x03)
#define SC_GET_DL(sc) (((sc)->haddr >> 4) & 0x03)
#define SC_GET_ST(sc) (((sc)->haddr >> 2) & 0x03)
#define SC_GET_SL(sc) ((sc)->haddr & 0x03)
#define SC_SET_VER(sc, v) ((sc)->ver_qos_flow = (sc)->ver_qos_flow & ~(0xF << 28) | (bpf_htonl(v) << 28))
#define SC_SET_QOS(sc, v) (((sc)->ver_qos_flow = (sc)->ver_qos_flow & ~(0xFF << 20) | (bpf_htonl(v) << 20)))
#define SC_SET_FLOW(sc, v) ((sc)->ver_qos_flow = (sc)->ver_qos_flow & ~0xFFFFF | (bpf_htonl(v)))
#define SC_SET_DT(sc, v) ((sc)->haddr = ((sc)->haddr & ~(0x3 << 6)) | (v << 6))
#define SC_SET_DL(sc, v) ((sc)->haddr = ((sc)->haddr & ~(0x3 << 4)) | (v << 4))
#define SC_SET_ST(sc, v) ((sc)->haddr = ((sc)->haddr & ~(0x3 << 2)) | (v << 2))
#define SC_SET_SL(sc, v) ((sc)->haddr = ((sc)->haddr & ~0x3) | v)

struct __attribute__((packed)) scionhdr {
	// Common header
	__u32 ver_qos_flow; // (4 bit) header version (= 0)
		// (8 bit) traffic class
		// (20 bit) mandatory flow id,
	__u8 next; // next header type
	__u8 len; // header length in units of 4 bytes
	__u16 payload; // payload length in bytes
	__u8 type; // path type
	__u8 haddr; // (2 bit) destination address type
		// (2 bit) destination address length
		// (2 bit) source address type
		// (2 bit) source address length
	__u16 rsv; // reserved

	// Address header
	union {
		struct dst_isd_as {
			__u16 dst_isd; // destination ISD
			__u8 dst_as[6]; // destination AS
		};
		__u64 dst;
	} dst;
	union {
		struct src_isd_as {
			__u16 src_isd; // source ISD
			__u8 src_as[6]; // source AS
		};
		__u64 src;
	} src;
};

/* Standard SCION path */

// PathMeta Header
// (6 bit) number of hop field in path segment 2
// (6 bit) number of hop field in path segment 1
// (6 bit) number of hop field in path segment 0
// (6 bit) reserved
// (2 bit) index of current info field
// (6 bit) index of current hop field
// Macros ending in "_HOST" take an argument in host byte order.
#define PATH_GET_SEG2_HOST(path) ((path)&0x3f)
#define PATH_GET_SEG1_HOST(path) (((path) >> 6) & 0x3f)
#define PATH_GET_SEG0_HOST(path) (((path) >> 12) & 0x3f)
#define PATH_GET_CURR_HF_HOST(path) (((path) >> 24) & 0x3f)
#define PATH_GET_CURR_INF_HOST(path) (((path) >> 30) & 0x03)
#define PATH_SET_SEG2_HOST(path, v) ((path) = (path) & ~0x3F | v)
#define PATH_SET_SEG1_HOST(path, v) ((path) = (path) & ~(0x3F << 6) | (v << 6))
#define PATH_SET_SEG0_HOST(path, v) ((path) = (path) & ~(0x3F << 12) | (v << 12))
#define PATH_SET_CURR_HF_HOST(path, v) ((path) = (path) & ~(0x3F << 24) | (v << 24))
#define PATH_SET_CURR_INF_HOST(path, v) ((path) = (path) & ~(0x3 << 30) | (v << 30))

typedef __u32 pathmetahdr;

#define INF_GET_CONS(info) ((info)->flags & 0x01)
#define INF_GET_PEER(info) ((info)->flags & 0x02)
#define INF_SET_CONS(info, v) ((info)->flags = (info)->flags & ~0x01 | v)
#define INF_SET_PEER(info, v) ((info)->flags = (info)->flags & ~0x02 | (v << 1))

struct __attribute__((packed)) infofield {
	__u8 flags; // (1 bit) construction direction flag
		// (1 bit) peering path flag
		// (6 bit) reserved flags
	__u8 rsv; // reserved
	__u16 seg_id; // SegID
	__u32 ts; // timestamp in Unix time
};

#define HF_GET_E_ALERT(hf) ((hf)->flags & 0x01)
#define HF_GET_I_ALERT(hf) ((hf)->flags & 0x02)
#define HF_SET_E_ALERT(hf, v) ((hf)->flags = (hf)->flags & ~0x01 | v)
#define HF_SET_I_ALERT(hf, v) ((hf)->flags = (hf)->flags & ~0x02 | (v << 1))

struct __attribute__((packed)) hopfield {
	__u8 flags; // (1 bit) cons egress router alert
		// (1 bit) cons ingress router alert
		// (6 bit) reserved flags
	__u8 exp; // expiry time
	__u16 ingress; // ingress interface in construction direction
	__u16 egress; // egress interface in construction direction
	__u8 mac[6]; // message authentication code
};

struct __attribute__((packed)) macinput {
	__u16 null0;
	__u16 beta;
	__u32 ts;
	__u8 null1;
	__u8 exp;
	__u16 ingress;
	__u16 egress;
	__u16 null2;
};

struct __attribute__((packed)) scmphdr {
	__u8 type;
	__u8 code;
	__u16 csum;
	//__u8 *info;
	//__u8 *data;
};

#endif // SCION_H_GUARD
