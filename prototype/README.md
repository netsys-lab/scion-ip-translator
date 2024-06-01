SCION-IP Translator Python Prototype
====================================

Prototype SCION-IP translator in Python. Works by encoding SCION addresses as
SCION-mapped IPv6 addresses that any IPv6 application can use.

The translator creates a tun interface and assigns a SCION-mapped IPv6 address
to it. Packets with a destination address matching the prefix fc00::/8 are
routed through the TUN interface. These packets are rewritten to SCION and
sent out the real network interface. SCION packets received from the network are
translated back to IPv6 enabling bidirectional communication.

Host can use either SCION-mapped IPv6 addresses or IPv4 addresses that are
translated to SCION-IPv4-mapped addresses similar to IPv4-mapped IPv6 addresses.

Packet IO on the network is handled by a single UDP socket bound to the port
usually occupied by the dispatcher.

Preparation
-----------
Requirements:
```bash
python3 -m venv .venv
. .venv/bin/activate
pip3 install -r requirements.txt
```

To update the generated gRPC files:
```bash
pip3 install grpcio-tools
./build_grpc.sh
```

Demo
----

### Local Topology with Mixed IPv4/6 Underlay
1. Run `sudo topology/setup.py` to create network namespaces and veths.
2. Create local SCION topology from `topology/tiny.topo`.
3. Modify SCION topology:
```bash
cd SCION_ROOT
cp -r gen/AS64512/* gen/AS0_0_fc00/
cp -r gen/AS64513/* gen/AS0_0_fc01/
cp -r gen/AS64514/* gen/AS0_0_fc02/
jq '.control_service["cs1-0_0_fc00-1"].addr |= sub("\\[(.*)\\]"; "10.128.0.2") |
    .discovery_service["cs1-0_0_fc00-1"].addr |= sub("\\[(.*)\\]"; "10.128.0.2") |
    .border_routers["br1-0_0_fc00-1"].internal_addr |= sub("\\[(.*)\\]"; "10.128.0.2")' \
    gen/AS0_0_fc00/topology.json | sponge gen/AS0_0_fc00/topology.json
sed -iE 's/"\[.*\]/"[10.128.0.2]/' gen/AS0_0_fc00/sd.toml
jq '.control_service["cs1-0_0_fc01-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:100::2]") |
    .discovery_service["cs1-0_0_fc01-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:100::2]") |
    .border_routers["br1-0_0_fc01-1"].internal_addr |= sub("\\[(.*)\\]"; "[fc00:10fc:100::2]")' \
    gen/AS0_0_fc01/topology.json | sponge gen/AS0_0_fc01/topology.json
sed -iE 's/"\[.*\]/"[10.128.1.2]/' gen/AS0_0_fc01/sd.toml
jq '.control_service["cs1-0_0_fc02-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:200::2]") |
    .discovery_service["cs1-0_0_fc02-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:200::2]") |
    .border_routers["br1-0_0_fc02-1"].internal_addr |= sub("\\[(.*)\\]"; "[fc00:10fc:200::2]")' \
    gen/AS0_0_fc02/topology.json | sponge gen/AS0_0_fc02/topology.json
sed -iE 's/"\[.*\]/"[10.128.2.2]/' gen/AS0_0_fc02/sd.toml
```
4. Run SCION
5. Run translators
```bash
sudo PYTHONPATH=../scapy-scion-int ip netns exec host0 ./scitun.py 10.128.0.1 veth0 -d 10.128.0.2:30255
sudo PYTHONPATH=../scapy-scion-int ip netns exec host1 ./scitun.py fc00:10fc:100::1/64 veth2 -d 10.128.1.2:30255
sudo PYTHONPATH=../scapy-scion-int ip netns exec host2 ./scitun.py fc00:10fc:200::1/64 veth4 -d 10.128.2.2:30255
```

Things to try:
- ping
```bash
sudo ip netns exec host1 ping fc00:10fc:200::1
sudo ip netns exec host2 ping fc00:10fc:100::1
sudo ip netns exec host0 ping fc00:10fc:200::1
sudo ip netns exec host1 ping fc00:10fc::ffff:a80:1
sudo ip netns exec host2 ping fc00:10fc::ffff:a80:1
```
- iperf3
```bash
sudo ip netns exec host1 iperf3 -s -p 5000
sudo ip netns exec host2 iperf3 -c fc00:10fc:100::1 -p 5000
```
- http server
```bash
(cd demo && sudo ip netns exec host1 python -m http.server --bind fc00:10fc:100::1 80)
sudo ip netns exec host2 curl http://[fc00:10fc:100::1]
```

Stop SCION and remove network namespaces:
```bash
./scion.sh stop
sudo ip netns del host0
sudo ip netns del host1
sudo ip netns del host2
```
