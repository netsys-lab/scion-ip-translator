#!/bin/env python3

import json
import os
import sys
import subprocess

if len(sys.argv) != 4:
    print("Usage: bwtest.sh EXP SCIOND SERVER")
    exit(-1)

BWTESTER="/opt/scion-apps/bin/scion-bwtestclient"
EXP=sys.argv[1]
SCIOND=sys.argv[2]
SERVER=sys.argv[3]
TIME=10
UDP_TARGET="10G"

length_array = list(range(100, 1500, 100))

data = {}
for LENGTH in length_array:
    bps = []
    for REP in range(TIME):
        print(f"UDP {LENGTH} bytes ({REP})")

        env = {"SCION_DAEMON_ADDRESS": SCIOND}
        cmd = [os.path.abspath(BWTESTER), "-s", SERVER, "-cs", f"1,{LENGTH},?,{UDP_TARGET}"]
        res = subprocess.run(cmd, env=env, capture_output=True)
        if res.returncode != 0:
            print(res.stderr.decode())
            exit(-1)

        cs = False
        for line in res.stdout.decode().splitlines():
            if cs == True and line.startswith("Achieved bandwidth:"):
                bps.append(float(line.removeprefix("Achieved bandwidth:").split()[0]))
                break
            if line.startswith("C->S"):
                cs = True
        else:
            print("unexpected output")
            exit(-1)

    data[LENGTH] = bps

with open(f"data/{EXP}_UDP.json", 'w') as file:
    json.dump(data, file, indent=4)
