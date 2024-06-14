## Isolate Translator in Separate Network Namespace

### PC 1
Veth: fc00-host <=> fc00-tra
Veth: fc01-host <=> fc01-tra

#### Namespace fc00
- fc00-host
  - IPv6: fc01:fc:0:1::1/64

#### Namespace fc00-tra
- fc00-tra
  - IPv6: fc01:fc:0:1::2/64

- enp4s0f0np0 (Link 1)
  - IP: 10.200.0.2/24
  - IPv6: fc01:fc::2/64, fd00:f00d:cafe:1::2/64

#### Namespace fc01
- fc00-host
  - IPv6: fc01:fc:100:1::1/64

#### Namespace fc01-tra
- fc00-tra
  - IPv6: fc01:fc:100:1::2/64

- enp4s0f1np1 (Link 2)
  - IP: 10.200.1.2/24
  - IPv6: fc01:fc:100::2/64, fd00:f00d:cafe:2::2/64

### PC 2
- enp1s0f0np0 (Link 1)
  - IP: 10.200.0.1/24
  - IPv6: fc01:fc::1/64, fd00:f00d:cafe:1::1/64
- enp1s0f1np1 (Link 2)
  - IP: 10.200.1.1/24
  - IPv6: fc01:fc:100::1/64, fd00:f00d:cafe:2::1/64

### Preparation
PC 1
```bash
sudo ip netns add fc00
sudo ip netns add fc00-tra
sudo ip netns add fc01
sudo ip netns add fc01-tra

sudo ip netns exec fc00 ip link add fc00-host type veth peer name fc00-tra netns fc00-tra
sudo ip netns exec fc01 ip link add fc01-host type veth peer name fc01-tra netns fc01-tra
sudo ip link set dev enp4s0f0np0 netns fc00-tra
sudo ip link set dev enp4s0f1np1 netns fc01-tra

sudo ip netns exec fc00-tra bash
ip addr add dev enp4s0f0np0 10.200.0.2/24
ip addr add dev enp4s0f0np0 fc01:fc::2/64
ip addr add dev enp4s0f0np0 fd00:f00d:cafe:1::2/64
ip link set lo up
ip link set enp4s0f0np0 up
ip addr add dev fc00-tra fc01:fc:0:1::2/64
ip link set fc00-tra up
ip route add fc00::/8 via fc01:fc::1
sysctl -w net.ipv6.conf.all.forwarding=1

sudo ip netns exec fc00 bash
ip addr add dev fc00-host fc01:fc:0:1::1/64
ip link set lo up
ip link set fc00-host up
ip route add fc00::/8 via fc01:fc:0:1::2

sudo ip netns exec fc01-tra bash
ip addr add dev enp4s0f1np1 10.200.1.2/24
ip addr add dev enp4s0f1np1 fc01:fc:100::2/64
ip addr add dev enp4s0f1np1 fd00:f00d:cafe:2::2/64
ip link set lo up
ip link set enp4s0f1np1 up
ip addr add dev fc01-tra fc01:fc:100:1::2/64
ip link set fc01-tra up
ip route add fc00::/8 via fc01:fc:100::1
sysctl -w net.ipv6.conf.all.forwarding=1

sudo ip netns exec fc01 bash
ip addr add dev fc01-host fc01:fc:100:1::1/64
ip link set lo up
ip link set fc01-host up
ip route add fc00::/8 via fc01:fc:100:1::2
```

### SCION Setup
PC 2
```bash
cd projects/scion
rm -r gen gen-cache gen-certs logs traces
./scion.sh topology -c topology/testbed.topo
cp -r gen/AS64512/* gen/AS0_0_fc00/
cp -r gen/AS64513/* gen/AS0_0_fc01/
jq '.control_service["cs16-0_0_fc00-1"].addr |= sub("\\[(.*)\\]"; "[fd00:f00d:cafe:1::1]") |
    .discovery_service["cs16-0_0_fc00-1"].addr |= sub("\\[(.*)\\]"; "[fd00:f00d:cafe:1::1]") |
    .border_routers["br16-0_0_fc00-1"].internal_addr |= sub("\\[(.*)\\]"; "[fc01:fc::1]") |
    .sigs["sig-1"] = {"ctrl_addr": "[fd00:f00d:cafe:1::2]:30256", "data_addr": "[fd00:f00d:cafe:1::2]:30056"}' \
    gen/AS0_0_fc00/topology.json | sponge gen/AS0_0_fc00/topology.json
jq '.control_service["cs16-0_0_fc01-1"].addr |= sub("\\[(.*)\\]"; "[fd00:f00d:cafe:2::1]") |
    .discovery_service["cs16-0_0_fc01-1"].addr |= sub("\\[(.*)\\]"; "[fd00:f00d:cafe:2::1]") |
    .border_routers["br16-0_0_fc01-1"].internal_addr |= sub("\\[(.*)\\]"; "[fc01:fc:100::1]") |
    .sigs["sig-1"] = {"ctrl_addr": "[fd00:f00d:cafe:2::2]:30256", "data_addr": "[fd00:f00d:cafe:2::2]:30056"}' \
    gen/AS0_0_fc01/topology.json | sponge gen/AS0_0_fc01/topology.json
./scion.sh run
tar -cf gen.tar gen gen-cache
```

PC 1
```bash
cd projects/scion
rm -r gen gen-cache gen-certs logs traces
scp PC2:~/projects/scion/gen.tar .
tar -xf gen.tar
sed -iE 's/"\[.*\]/"[::1]/' gen/AS0_0_fc00/sd.toml
sed -iE 's/"\[.*\]/"[::1]/' gen/AS0_0_fc01/sd.toml

sudo -v
mkdir logs
sudo ip netns exec fc00-tra bin/daemon --config gen/AS0_0_fc00/sd.toml >> logs/sd16-0_0_fc00.log 2>&1 &
sudo ip netns exec fc00-tra bin/dispatcher --config gen/dispatcher/disp.toml >> logs/dispatcher1.log 2>&1 &
sudo ip netns exec fc01-tra bin/daemon --config gen/AS0_0_fc01/sd.toml >> logs/sd16-0_0_fc01.log 2>&1 &
sudo ip netns exec fc01-tra bin/dispatcher --config gen/dispatcher/disp.toml >> logs/dispatcher2.log 2>&1 &

sudo ip netns exec fc00-tra bash
bin/scion showpaths --sciond [::1]:30255 16-0:0:fc01
bin/scion ping --sciond [::1]:30255 16-0:0:fc01,fc01:fc:100::2

sudo ip netns exec fc01-tra bash
bin/scion showpaths --sciond [::1]:30255 16-0:0:fc00
bin/scion ping --sciond [::1]:30255 16-0:0:fc00,fc01:fc::2
```

### SIG Setup
- AS 0:0:fc00 (gen/AS0_0_fc00/sig.toml)
```toml
[log.console]
  level = "info"
[metrics]
  prometheus = "[::1]:30200"
[sciond_connection]
  address = "[::1]:30255"
  initial_connect_period = "30s"
[gateway]
  id = "gateway"
  traffic_policy_file = "/home/lars/projects/scion/gen/AS0_0_fc00/traffic.policy"
  ctrl_addr = "[fd00:f00d:cafe:1::2]:30256"
  data_addr = "[fd00:f00d:cafe:1::2]:30056"
  probe_addr = "[fd00:f00d:cafe:1::2]:30856"
[tunnel]
  name = "sig"
  src_ipv6 = "fc01:fc:0:1::1"
```
- gen/AS0_0_fc00/traffic.policy
```json
{
  "ConfigVersion": 1,
  "ASes": {
    "16-0:0:fc01": {
      "Nets": ["fc01:fc:100:1::/64"]
    }
  }
}
```

- AS 0:0:fc00 (gen/AS0_0_fc01/sig.toml)
```toml
[log.console]
  level = "info"
[metrics]
  prometheus = "[::1]:30200"
[sciond_connection]
  address = "[::1]:30255"
  initial_connect_period = "30s"
[gateway]
  id = "gateway"
  traffic_policy_file = "/home/lars/projects/scion/gen/AS0_0_fc01/traffic.policy"
  ctrl_addr = "[fd00:f00d:cafe:2::2]:30256"
  data_addr = "[fd00:f00d:cafe:2::2]:30056"
  probe_addr = "[fd00:f00d:cafe:2::2]:30856"
[tunnel]
  name = "sig"
  src_ipv6 = "fc01:fc:100:1::1"
```
- gen/AS0_0_fc01/traffic.policy
```json
{
  "ConfigVersion": 1,
  "ASes": {
    "16-0:0:fc00": {
      "Nets": ["fc01:fc:0:1::/64"]
    }
  }
}
```

Run Gateways:
```bash
sudo ip netns exec fc00-tra bin/gateway --config gen/AS0_0_fc00/sig.toml >> logs/gateway1.log 2>&1 &
sudo ip netns exec fc01-tra bin/gateway --config gen/AS0_0_fc01/sig.toml >> logs/gateway2.log 2>&1 &
sudo ip netns exec fc00-tra ip route add fc01:fc:100:1::/64 dev sig
sudo ip netns exec fc01-tra ip route add fc01:fc:0:1::/64 dev sig
```

### Test SIG
```bash
# AS 0:0:fc00
nc -6 -l fc01:fc:0:1::1 5000
# AS 0:0:fc01
nc fc01:fc:0:1::1 5000
```
```bash
# AS 0:0:fc00
iperf3 -6 -s fc01:fc:0:1::1 -p 5000
# AS 0:0:fc01
iperf3 -6 -c fc01:fc:0:1::1 -p 5000
```

### Direct IP Routing
PC 2
```bash
sudo ip route add fc01:fc:0:1::2/64 via fc01:fc::2
sudo ip route add fc01:fc:100:1::2/64 via fc01:fc:100::2
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Disable routing again:
```bash
sudo ip route del fc01:fc:0:1::2/64 via fc01:fc::2
sudo ip route del fc01:fc:100:1::2/64 via fc01:fc:100::2
sudo sysctl -w net.ipv6.conf.all.forwarding=0
```

### SCION-IP Translator
```bash
cd master-thesis-code/translation
sudo ip netns exec fc00-tra build/loader --sciond [::1]:30255 -i enp4s0f0np0 -e enp4s0f0np0
cd master-thesis-code/translation
sudo ip netns exec fc01-tra build/loader --sciond [::1]:30255 -i enp4s0f1np1 -e enp4s0f1np1
```

```bash
sudo ip netns exec fc00-tra tc qdisc delete dev enp4s0f0np0 clsact
sudo ip netns exec fc01-tra tc qdisc delete dev enp4s0f1np1 clsact
```
