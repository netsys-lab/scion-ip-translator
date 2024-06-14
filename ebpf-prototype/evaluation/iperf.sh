#!/bin/bash

set -e

if [ $# -ne 3 ]; then
    echo Usage: iperf.sh EXP SERVER PORT
    exit
fi

# Use iperf3 version 3.17.1
IPERF3=iperf3
IPERF_ARGS="-J --get-server-output"
EXP=$1
SERVER=$2
PORT=$3
TIME=10
UDP_TARGET=100G

declare -a streams_array=(1 2 4 8)
declare -a mss_array=($(seq 100 100 1300) 1324)
declare -a length_array=($(seq 100 100 1300) 1324)

for STREAMS in "${streams_array[@]}"
do
    for MSS in "${mss_array[@]}"
    do
        echo "TCP ${STREAMS} stream(s), ${MSS} bytes MSS"
        $IPERF3 -c $SERVER -p $PORT -t $TIME $IPERF_ARGS -M ${MSS} -P $STREAMS \
            > "data/${EXP}_TCP_${MSS}B_${STREAMS}S.json"
        sleep 1
    done
done

for STREAMS in "${streams_array[@]}"
do
    for LENGTH in "${length_array[@]}"
    do
        echo "UDP ${STREAMS} stream(s), ${LENGTH} bytes"
        $IPERF3 -c $SERVER -p $PORT -t $TIME $IPERF_ARGS -u -b $UDP_TARGET -l $LENGTH -P $STREAMS \
            > "data/${EXP}_UDP_${LENGTH}B_${STREAMS}S.json"
        sleep 1
    done
done
