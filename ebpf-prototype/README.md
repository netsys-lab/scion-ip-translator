# SCION IPv6 Translation

Transparent in-kernel translation of SCION inbound and IPv6 outbound packets

## Building

```bash
cmake -S . -B build
cmake --build build
```

## Running

The resulting binary can be found under `build/loader`.
Run with `--help` flag to see usage.

Example usage:
```
build/loader -i eth0 -e eth0 -d [::1]:30255
```

### Stopping

Due to a bug with the multithreaded code, `^C` currently does not work and the
process has to be killed manually. This can be achieved by issuing `sudo pkill
-KILL loader` or by suspending and then killing the process via `^Z` and `kill
%1`.

In order to properly remove all components, that have not been removed by the
cleanup code, you also have to delete the qdisc that was created for the eBPF
program via `sudo tc qdisc delete dev eth0 clsact` (here with eth0 as example
interface).

## License and Attribution

(c) 2023-2024 Florian Gallrein <florian@gallrein.de>
(c) 2024 Lars-Christian Schulz <lschulz@ovgu.de>

The software is available either under the MIT license or GPL-2.0-or-later at
your choice.

Some files included in this repository are from the
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) and the Linux
kernel and may be distributed under different terms.
