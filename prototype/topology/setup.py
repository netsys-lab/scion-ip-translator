#!/bin/env python3

import pyroute2
from pyroute2 import netns

netns.create("host0")
netns.create("host1")
netns.create("host2")
with pyroute2.IPRoute() as ipr:
    ipr.link("add", ifname="veth1", kind="veth", peer={"ifname": "veth0", "net_ns_fd": "host0"})
    ipr.link("add", ifname="veth3", kind="veth", peer={"ifname": "veth2", "net_ns_fd": "host1"})
    ipr.link("add", ifname="veth5", kind="veth", peer={"ifname": "veth4", "net_ns_fd": "host2"})

    with pyroute2.NetNS("host0") as host:
        lo = host.link_lookup(ifname="lo")[0]
        host.addr("add", index=lo, address="::1", mask=128)
        host.link("set", index=lo, state="up")

        veth = host.link_lookup(ifname="veth0")[0]
        host.addr("add", index=veth, address="10.128.0.1", mask=24)
        host.link("set", index=veth, state="up")

    veth1 = ipr.link_lookup(ifname="veth1")[0]
    ipr.addr("add", index=veth1, address="10.128.0.2", mask=24)
    ipr.link("set", index=veth1, state="up")

    with pyroute2.NetNS("host1") as host:
        lo = host.link_lookup(ifname="lo")[0]
        host.addr("add", index=lo, address="::1", mask=128)
        host.link("set", index=lo, state="up")

        veth = host.link_lookup(ifname="veth2")[0]
        host.addr("add", index=veth, address="10.128.1.1", mask=24)
        host.addr("add", index=veth, address="fc00:10fc:100::1", mask=64)
        host.link("set", index=veth, state="up")

    veth3 = ipr.link_lookup(ifname="veth3")[0]
    ipr.addr("add", index=veth3, address="10.128.1.2", mask=24)
    ipr.addr("add", index=veth3, address="fc00:10fc:100::2", mask=64)
    ipr.link("set", index=veth3, state="up")

    with pyroute2.NetNS("host2") as host:
        lo = host.link_lookup(ifname="lo")[0]
        host.addr("add", index=lo, address="::1", mask=128)
        host.link("set", index=lo, state="up")

        veth = host.link_lookup(ifname="veth4")[0]
        host.addr("add", index=veth, address="10.128.2.1", mask=24)
        host.addr("add", index=veth, address="fc00:10fc:200::1", mask=64)
        host.link("set", index=veth, state="up")

    veth5 = ipr.link_lookup(ifname="veth5")[0]
    ipr.addr("add", index=veth5, address="10.128.2.2", mask=24)
    ipr.addr("add", index=veth5, address="fc00:10fc:200::2", mask=64)
    ipr.link("set", index=veth5, state="up")
