#!/bin/env python3

import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt


STREAMS = [1, 2, 4, 8]
MSS = list(range(100, 1500, 100))
UDP_SIZE = list(range(100, 1400, 100)) + [1324]
SCI_SIZE = list(range(100, 1400, 100)) + [1324]

MARKERS = ["v", "^", "o", "s", "*"]


def load_iperf3(dir, exp, proto):
    res = defaultdict(dict)
    for streams in STREAMS:
        for size in (MSS if proto == "TCP" else UDP_SIZE):
            try:
                with open(Path(dir)/"{}_{}_{}B_{}S.json".format(exp, proto, size, streams), 'r') as file:
                    d = json.load(file)
                if d["start"]["test_start"]["reverse"] == 0:
                    bps = [i["sum"]["bits_per_second"] for i in d["server_output_json"]["intervals"]]
                else:
                    bps = [i["sum"]["bits_per_second"] for i in d["intervals"]]
                res[streams][size] = np.array(bps)
            except FileNotFoundError:
                continue
    return res


def load_bwtester(dir, exp):
    res = {}
    with open(Path(dir)/"{}_UDP.json".format(exp)) as file:
        d = json.load(file)
    for size, measurements in d.items():
        res[int(size)] = np.array(measurements)
    return res


def mean_of_center(x, low, high):
    return np.mean(sorted(x)[int(low*len(x)):int(high*len(x))])


def add_to_plot(ax, d, label, marker='o'):
    x = sorted(d.keys())
    y = 1e-9 * np.array([mean_of_center(bps, 0.1, 0.9) for size, bps in sorted(d.items())])
    lo = 1e-9 * np.array([np.quantile(bps, 0.1) for size, bps in sorted(d.items())])
    hi = 1e-9 * np.array([np.quantile(bps, 0.9) for size, bps in sorted(d.items())])
    ax.errorbar(x, y, yerr=(y - lo, hi - y), marker=marker, capsize=5, label=label)
    return ax


def plot_tcp():
    tcp = {}
    tcp["IP"] = load_iperf3("data", "IP", "TCP")
    tcp["SIG"] = load_iperf3("data", "SIG", "TCP")
    tcp["TRA"] = load_iperf3("data", "TRA", "TCP")

    fig, ax = plt.subplots(1, figsize=(8, 5))
    add_to_plot(ax, tcp["IP"][1], "Direct IP (no TSO)", marker="^")
    add_to_plot(ax, tcp["TRA"][1], "SCION-IP Translator", marker="o")
    add_to_plot(ax, tcp["SIG"][1], "SCION-IP Gateway", marker="v")
    ax.set_xlabel("MSS [bytes]")
    ax.set_ylabel("Throughput [Gbit/s]")
    ax.set_xlim(50, 1400)
    ax.set_ylim(0, 6)
    ax.set_title("(b) TCP")
    ax.legend(loc="upper left")

    return fig, ax


def plot_udp():
    udp = {}
    udp["IP"] = load_iperf3("data", "IP", "UDP")
    udp["SIG"] = load_iperf3("data", "SIG", "UDP")
    udp["TRA"] = load_iperf3("data", "TRA", "UDP")

    fig, ax = plt.subplots(1, figsize=(8, 5))
    add_to_plot(ax, udp["IP"][1], "Direct IP", marker="^")
    add_to_plot(ax, udp["TRA"][1], "SCION-IP Translator", marker="o")
    add_to_plot(ax, udp["SIG"][1], "SCION-IP Gateway", marker="v")
    ax.set_xlabel("Payload [bytes]")
    ax.set_ylabel("Throughput [Gbit/s]")
    ax.set_xlim(50, 1400)
    ax.set_ylim(0, 5)
    ax.set_title("(a) UDP")
    ax.legend(loc="upper left")

    return fig, ax


fig, ax = plot_udp()
fig.savefig("eval_udp.pdf")
fig, ax = plot_tcp()
fig.savefig("eval_tcp.pdf")
