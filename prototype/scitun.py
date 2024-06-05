#!/bin/env python3
# Copyright (c) 2024 Lars-Christian Schulz

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import fcntl
import ipaddress
import os
import selectors
import socket
import struct
import time
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address, IPv6Interface, IPv6Network
from typing import Optional, Tuple, Union

import pyroute2
from scapy.layers.inet import IP
from scapy.layers.inet6 import TCP, UDP, ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy_scion.layers.scion import SCION, EmptyPath, SCIONPath
from scapy_scion.layers.scmp import SCMP, EchoReply, EchoRequest, SCMPTypeNumbers

from daemon import Daemon

IPAddress = Union[IPv4Address, IPv6Address]
IPInterface = Union[IPv4Interface, IPv6Interface]

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x00000001
IFF_NO_PI = 0x00001000

TUN_PKT_STRIP = 1
ETH_P_IP = 0x0800
ETH_P_IPv6 = 0x86dd

SCION_PREFIX_LEN = 8
SCION_PREFIX = 0xfc << (128 - SCION_PREFIX_LEN)
SCION_NETWORK = IPv6Network((SCION_PREFIX, SCION_PREFIX_LEN))

class InvalidArgument(Exception):
    pass


def map_ipv4(isd: int, asn: int, interface: IPv4Address) -> IPv6Address:
    if not 0 <= isd < 2**12:
        raise InvalidArgument("ISD cannot be encoded")
    if int(asn) < 2**19:
        encoded_asn = int(asn)
    elif 0x2_0000_0000 <= int(asn) <= 0x2_0007_ffff:
        encoded_asn = (1 << 19) | (int(asn) & 0x7ffff)
    else:
        raise InvalidArgument("ASN cannot be encoded")

    ip = SCION_PREFIX | (isd << 108) | (encoded_asn << 88)
    ip |= 0xffff << 32
    ip |= int.from_bytes(interface.packed, "big")

    return IPv6Address(ip)


def unmap_ipv6(ip: IPv6Address, subnet_bits: int = 8
               ) -> Tuple[int, int, int, int, Union[IPv4Address, int]]:
    if not ip in SCION_NETWORK:
        raise InvalidArgument("not a SCION-mapped IPv6 address")

    ip = int(ip)
    interface = ip & 0xffff_ffff_ffff_ffff
    subnet = (ip >> 64) & ~(~0 << subnet_bits)
    local_prefix = (ip >> (64 + subnet_bits)) & ~(~0 << (24 - subnet_bits))
    asn = (ip >> 88) & 0xfffff
    isd = (ip >> 108) & 0xfff

    if asn & (1 << 19):
        asn = 0x2_0000_0000 | (asn & 0x7ffff)

    if interface & (0xffffffff << 32) == (0x0000ffff << 32):
        if local_prefix == 0 and subnet == 0:
            interface = IPv4Address(interface & 0xffffffff)

    return isd, asn, local_prefix, subnet, interface


def parse_path(raw: bytes):
    if len(raw) == 0:
        return EmptyPath()
    else:
        return SCIONPath(raw)


def split_addr(addr: str) -> Tuple[IPAddress, int]:
    if addr == "":
        return ("", 0)
    colon = addr.rfind(":")
    if colon == -1:
        raise Exception("Invalid router IP")
    ip, port = addr[:colon], addr[colon+1:]
    return ipaddress.ip_address(ip.strip("[]")), int(port)


class PathCache:
    def __init__(self, daemon_addr: str):
        self.daemon = Daemon(daemon_addr)
        self.paths = {}

    def lookup(self, dst_ia: int) -> Optional[Tuple[SCIONPath, Tuple[IPAddress, int]]]:
        try:
            paths = self.paths[dst_ia]
        except KeyError:
            paths = [(parse_path(raw), split_addr(router)) for raw, router in self.daemon.get_paths(dst_ia)]
            self.paths[dst_ia] = paths
        return paths[0] if len(paths) > 0 else None

    @property
    def local_ia(self) -> Tuple[int, int]:
        return (
            (self.daemon.local_ia >> 48) & 0xffff,
            self.daemon.local_ia & 0xffff_ffffffff
        )


class TunInterface:
    def __init__(self, name: str):
        self.tun_name = name

        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC)

        ifreq = struct.pack("16sH", self.tun_name.encode("ascii"), IFF_TUN)
        res = fcntl.ioctl(self.fd, TUNSETIFF, ifreq)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def read(self) -> Tuple[IP | IPv6, int]:
        buffer =  os.read(self.fd, 2028)

        flags = int.from_bytes(buffer[0:2], 'big')
        proto =  int.from_bytes(buffer[2:4], 'big')
        packet = buffer[4:]

        if flags & TUN_PKT_STRIP != 0:
            print("Packet truncated!")

        if proto == ETH_P_IP:
            return IP(packet), len(packet)
        elif proto == ETH_P_IPv6:
            return IPv6(packet), len(packet)
        else:
            return None, 0

    def write(self, pkt: IP | IPv6) -> int:
        proto = ETH_P_IPv6 if isinstance(pkt, IPv6) else ETH_P_IP
        header = struct.pack(">HH", 0, proto)
        buffer = header + bytes(pkt)
        return os.write(self.fd, buffer) - 4


def icmp_to_scmp(l4):
    if l4.type == 128:
        return SCMP(
            Type="Echo Request",
            Message=EchoRequest(
                Identifier=l4.id,
                SequenceNumber=l4.seq,
                Data=l4.data
            )
        )

    elif l4.type == 129:
        return SCMP(
            Type="Echo Reply",
            Message=EchoReply(
                Identifier=l4.id,
                SequenceNumber=l4.seq,
                Data=l4.data
            )
        )

    else:
        return None


def scmp_to_icmp(l4: SCMP):
    if l4.Type == SCMPTypeNumbers["Echo Request"]:
        return ICMPv6EchoRequest(
            id=l4.Message.Identifier,
            seq=l4.Message.SequenceNumber,
            data=l4.Message.Data
        )

    elif l4.Type == SCMPTypeNumbers["Echo Reply"]:
        return ICMPv6EchoReply(
            id=l4.Message.Identifier,
            seq=l4.Message.SequenceNumber,
            data=l4.Message.Data
        )

    else:
        return None


def translate_egress(pkt, host_ip: IPv6Address, hostPort: int, path_cache: PathCache):
    if not isinstance(pkt[0], IPv6):
        return None, None

    ip_dst = IPv6Address(pkt.dst)
    if ip_dst not in SCION_NETWORK:
        return None, None

    isd, asn, prefix, subnet, host = unmap_ipv6(ip_dst)
    if isinstance(host, IPv4Address):
        dst_host = host
    else:
        dst_host = ip_dst

    path = path_cache.lookup((isd << 48) | asn)
    if path is None:
        return None, None

    l4 = pkt.payload
    pkt.remove_payload()

    if pkt.nh == 6 or pkt.nh == 17: # TCP or UDP
        pass
    elif pkt.nh == 58: # ICMPv6
        l4 = icmp_to_scmp(l4)
        if l4 is None:
            return None, None
    else:
        return None, None

    if isinstance(path[0], EmptyPath):
        next_hop = (dst_host, hostPort) # (dst_host, l4.dport)
    else:
        next_hop = path[1]

    # Construct SCION header
    local_isd, local_asn = path_cache.local_ia
    scion = SCION(
        DT = 0, DL = 16 if dst_host.version == 6 else 4,
        ST = 0, SL = 16 if host_ip.version == 6 else 4,
        DstISD = isd,
        DstAS = asn,
        SrcISD = local_isd,
        SrcAS = local_asn,
        DstHostAddr=str(dst_host),
        SrcHostAddr=str(host_ip),
        Path=path[0],
    )

    pkt = scion / l4
    return pkt, next_hop


def translate_ingress(pkt: SCION, tun_ip: IPv6Interface):
    if not isinstance(pkt, SCION):
        return None

    if pkt.DT == 0:
        if pkt.DL == 4:
            dst = map_ipv4(pkt.DstISD, pkt.DstAS, IPv4Address(pkt.DstHostAddr))
        elif pkt.DL == 16:
            dst = IPv6Address(pkt.DstHostAddr)
        else:
            return None
    else:
        return None

    if dst != tun_ip.ip:
        return None

    if pkt.ST == 0:
        if pkt.SL == 4:
            src = map_ipv4(pkt.SrcISD, pkt.SrcAS, IPv4Address(pkt.SrcHostAddr))
        elif pkt.SL == 16:
            src = IPv6Address(pkt.SrcHostAddr)
            if src not in SCION_NETWORK:
                return None
        else:
            return None
    else:
        return None

    l4 = pkt.payload
    if isinstance(l4, UDP):
        l4.chksum = None # recalculate checksum
    elif isinstance(l4, TCP):
        l4.chksum = None # recalculate checksum
    elif isinstance(l4, SCMP):
        l4 = scmp_to_icmp(l4)
        if l4 is None:
            return None
    else:
        return None

    ip = IPv6(
        dst = str(dst),
        src = str(src)
    )

    return ip / l4


def open_socket(host_ip: IPInterface, port: int, netif: str):
    if host_ip.version == 4:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((str(host_ip.ip), port))
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.bind((str(host_ip.ip), port, 0, 0))
    try:
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, netif.encode("ascii"))
        return sock
    except:
        sock.close()
        raise


def run_translation(host_ip: IPv6Interface, netif: str, tunif: str, port: int, daemon_addr: str):
    path_cache = PathCache(daemon_addr)
    sel = selectors.DefaultSelector()

    with TunInterface(tunif) as tun:
        sel.register(tun.fd, selectors.EVENT_READ, "tun")

        with pyroute2.IPRoute() as ipr:
            net0 = ipr.link_lookup(ifname=netif)[0]
            tun0 = ipr.link_lookup(ifname=tunif)[0]
            if host_ip.ip.version == 4:
                tun_ip = IPv6Interface((map_ipv4(*path_cache.local_ia, host_ip.ip), 40))
            else:
                tun_ip = host_ip
            ipr.addr("add", index=tun0, address=str(tun_ip.ip), mask=tun_ip.network.prefixlen)
            ipr.link("set", index=tun0, state="up")
            ipr.route("add", dst="fc00::", dst_len=8, oif=tun0)

            with open_socket(host_ip, port, netif) as sock:
                sel.register(sock, selectors.EVENT_READ, "udp")

                while True:
                    events = sel.select()
                    for key, mask in events:
                        if key.data == "tun":
                            packet, size= tun.read()
                            t = time.monotonic() % 1e4
                            print(f"[{t:9.4f}] TUN: {packet} ({size} B) >>>", end=" ")
                            pkt, dest = translate_egress(packet, host_ip.ip, port, path_cache)
                            if pkt is not None:
                                print(f"{pkt} to {dest}", end=" ")
                                if dest[0].version == host_ip.version:
                                    size = sock.sendto(bytes(pkt), (str(dest[0]), dest[1]))
                                    print(f"({size} B)")
                                else:
                                    print("error: host address type mismatch")
                            else:
                                print("drop")

                        elif key.data == "udp":
                            raw, sender = sock.recvfrom(2048)
                            packet = SCION(raw)
                            t = time.monotonic() % 1e4
                            print(f"[{t:9.4f}] UDP: {packet} ({len(raw)} B) from {sender} >>>", end=" ")
                            pkt = translate_ingress(packet, tun_ip)
                            if pkt is not None:
                                print(pkt, end=" ")
                                size = tun.write(pkt)
                                print(f"({size} B)")
                            else:
                                print("drop")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", type=ipaddress.ip_interface, help="Host address with mask")
    parser.add_argument("interface", type=str, help="Main network interface")
    parser.add_argument("-d", "--daemon", type=str, default="127.0.0.1:30255", help="SCION daemon address")
    parser.add_argument("-t", "--tunnel", type=str, metavar="TUN", default="scitun", help="Name of the tunnel device")
    parser.add_argument("-p", "--port", type=int, default=30041, help="UDP port for SCION packet IO")
    args = parser.parse_args()

    try:
        run_translation(args.ip, args.interface, args.tunnel, args.port, args.daemon)
    except KeyboardInterrupt:
        print("Exiting")


if __name__ == "__main__":
    main()
