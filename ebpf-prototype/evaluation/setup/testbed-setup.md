Testbed Setup
=============

                                                Epyc1
Epyc2   enp129s0np0 fc01:fc::2/64           <-> fc01:fc::1/64           enp129s0np0
                    fd00:f00d:cafe:1::2/64  <-> fd00:f00d:cafe:1::1/64  enp129s0np0
        enp65s0np0  fd00:f00d:cafe:2::3/64
        lo          fd01:fc::2/64

Epyc3   enp129s0np0 fc01:fc:100::2/64       <-> fc01:fc:100::1/64       enp65s0np0
                    fd00:f00d:cafe:2::2/64  <-> fd00:f00d:cafe:2::1/64  enp65s0np0
        enp65s0np0  fd00:f00d:cafe:1::3/64
        lo          fd01:fc:100::2/64

### Epyc1
```bash
sudo ip addr add dev enp129s0np0 fc01:fc::1/64
sudo ip addr add dev enp129s0np0 fd00:f00d:cafe:1::1/64
sudo ip addr add dev enp65s0np0 fc01:fc:100::1/64
sudo ip addr add dev enp65s0np0 fd00:f00d:cafe:2::1/64
sudo ip link set dev enp129s0np0 up
sudo ip link set dev enp65s0np0 up
```

### Epyc2
```bash
sudo ip addr add dev enp129s0np0 fc01:fc::2/64
sudo ip addr add dev enp129s0np0 fd00:f00d:cafe:1::2/64
sudo ip addr add dev enp65s0np0 fd00:f00d:cafe:2::3/64
sudo ip addr add dev lo fd01:fc::2/64
sudo ip link set dev enp129s0np0 up
sudo ip link set dev enp65s0np0 up
```

### Epyc3
```bash
sudo ip addr add dev enp129s0np0 fc01:fc:100::2/64
sudo ip addr add dev enp129s0np0 fd00:f00d:cafe:2::2/64
sudo ip addr add dev enp65s0np0 fd00:f00d:cafe:1::3/64
sudo ip addr add dev lo fd01:fc:100::2/64
sudo ip link set dev enp129s0np0 up
sudo ip link set dev enp65s0np0 up
```

### SCION Setup
Topology:
```yaml
---
ASes:
  "16-0:0:fc00":
    core: true
    voting: true
    authoritative: true
    issuing: true
    underlay: UDP/IPv6
    mtu: 1452
  "16-0:0:fc01":
    core: true
    voting: true
    authoritative: true
    issuing: true
    underlay: UDP/IPv6
    mtu: 1452
links:
  - {a: "16-0:0:fc00#1", b: "16-0:0:fc01#1", linkAtoB: CORE, underlay: UDP/IPv6, mtu: 1452}
```
```bash
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
```

Epyc1:
```bash
./scion.sh run
tar -cf gen.tar gen gen-cache
scp gen.tar NetSys-Epyc2:/opt/scion
scp gen.tar NetSys-Epyc3:/opt/scion
```

Epyc2:
```bash
cd /opt/scion
rm -r gen gen-cache gen-certs logs traces
tar -xf gen.tar
sed -iE 's/"\[.*\]/"[::1]/' gen/AS0_0_fc00/sd.toml
tools/supervisor.sh start as16-0_0_fc00:sd16-0_0_fc00 dispatcher
bin/scion showpaths --sciond [::1]:30255 16-0:0:fc01
snet-echo --sciond [::1]:30255 --local [fc01:fc::2]:5000 --remote 16-64513,[fc01:fc:100::2]:5000
```

Epyc3:
```bash
cd /opt/scion
rm -r gen gen-cache gen-certs logs traces
tar -xf gen.tar
sed -iE 's/"\[.*\]/"[::1]/' gen/AS0_0_fc01/sd.toml
tools/supervisor.sh start as16-0_0_fc01:sd16-0_0_fc01 dispatcher
bin/scion showpaths --sciond [::1]:30255 16-0:0:fc00
snet-echo --sciond [::1]:30255 --local [fc01:fc:100::2]:5000
```

### eBPF SCION-IP Translator
Epyc2:
```bash
sudo ip -6 route add fc08::/8 dev enp129s0np0
sudo /opt/translator/loader --sciond [::1]:30255 -i enp129s0np0 -e enp129s0np0
nc -l 50000
```

Epyc3:
```bash
sudo ip -6 route add fc08::/8 dev enp129s0np0
sudo /opt/translator/loader --sciond [::1]:30255 -i enp129s0np0 -e enp129s0np0
nc fc01:fc::2 50000
```

### SIG Configuration
SIG Configuration (put in `/opt/scion/gen/<asn>/sig.toml`)
- For AS 16-0:0:fc00 (`/opt/scion/gen/AS0_0_fc00/sig.toml`)
```toml
[log.console]
  level = "debug"
[metrics]
  prometheus = "[::1]:30200"
[sciond_connection]
  address = "[::1]:30255"
  initial_connect_period = "30s"
[gateway]
  id = "gateway"
  traffic_policy_file = "/opt/scion/gen/AS0_0_fc00/traffic.policy"
  ctrl_addr = "[fd00:f00d:cafe:1::2]:30256"
  data_addr = "[fd00:f00d:cafe:1::2]:30056"
  probe_addr = "[fd00:f00d:cafe:1::2]:30856"
[tunnel]
  name = "sig"
  src_ipv6 = "fd01:fc::2"
```
- For AS 16-0:0:fc01 (`/opt/scion/gen/AS0_0_fc01/sig.toml`)
```toml
[log.console]
  level = "debug"
[metrics]
  prometheus = "[::1]:30200"
[sciond_connection]
  address = "[::1]:30255"
  initial_connect_period = "30s"
[gateway]
  id = "gateway"
  traffic_policy_file = "/opt/scion/gen/AS0_0_fc01/traffic.policy"
  ctrl_addr = "[fd00:f00d:cafe:2::2]:30256"
  data_addr = "[fd00:f00d:cafe:2::2]:30056"
  probe_addr = "[fd00:f00d:cafe:2::2]:30856"
[tunnel]
  name = "sig"
  src_ipv6 = "fd01:fc:100::2"
```

#### Traffic Policy File (`/opt/scion/gen/<asn>/traffic.policy`)
- For AS 16-0:0:fc00 (`/opt/scion/gen/AS0_0_fc00/traffic.policy`)
```json
{
  "ConfigVersion": 1,
  "ASes": {
    "16-0:0:fc01": {
      "Nets": ["fd01:fc:100::/64"]
    }
  }
}
```
- For AS 16-0:0:fc01 (`/opt/scion/gen/AS0_0_fc01/traffic.policy`)
```json
{
  "ConfigVersion": 1,
  "ASes": {
    "16-0:0:fc00": {
      "Nets": ["fd01:fc::/64"]
    }
  }
}
```

#### Routing Policy File (`/opt/scion/gen/<asn>/routing.policy`)
Doesn't seem to be necessary. Maybe only for dynamic prefix discovery and
traffic policy is used for static prefixes.
- For AS 16-0:0:fc00
```
advertise 16-0:0:fc00 16-0:0:fc01 fc10:fc00:0:1::/64
accept            0-0         0-0               ::/0
```
- For AS 16-0:0:fc01
```
advertise 16-0:0:fc01 16-0:0:fc00 fc10:fc01:0:1::/64
accept            0-0         0-0               ::/0
```
Note: Annoyingly blank lines or commented out lines are not allowed by the
parser. Be extra careful to not add blank lines to the end of the file.

#### Supervisord
Append to `gen/supervisord.conf`
```
[program:sig-fc00]
autostart = false
autorestart = false
environment = TZ=UTC
stdout_logfile = logs/sig_fc00.log
redirect_stderr = true
startretries = 0
command = bin/gateway --config gen/AS0_0_fc00/sig.toml

[program:sig-fc01]
autostart = false
autorestart = false
environment = TZ=UTC
stdout_logfile = logs/sig_fc01.log
redirect_stderr = true
startretries = 0
command = bin/gateway --config gen/AS0_0_fc01/sig.toml
```

Make sure gateway has CAP_NET_ADMIN (to create tun device):
```bash
sudo setcap cap_net_admin=epi bin/gateway
````

Start sig with:
```bash
tools/supervisor.sh reload # reload (if config changed, kills all processes)
tools/supervisor.sh start sig-fc00 # AS 16-0:0:fc00
tools/supervisor.sh start sig-fc01 # AS 16-0:0:fc01
```

### Test intra-AS Translation
Epyc3:
```bash
tools/supervisor.sh stop as16-0_0_fc01:sd16-0_0_fc01 dispatcher
sudo ip addr add dev enp129s0np0 fc01:fc::3/64
sudo ip addr add dev enp129s0np0 fd00:f00d:cafe:1::3/64
sed -iE 's/"\[.*\]/"[::1]/' gen/AS0_0_fc00/sd.toml
tools/supervisor.sh start as16-0_0_fc00:sd16-0_0_fc00 dispatcher
```

### Epyc 1 as IP Router
Epyc1:
```bash
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Epyc2:
```bash
sudo ip -6 route add fc01:fc:100::/64 via fc01:fc::1
```

Epyc3:
```bash
sudo ip -6 route add fc01:fc::/64 via fc01:fc:100::1
```
