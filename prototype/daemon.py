#!/bin/env python3

from typing import Tuple

import grpc
import proto.daemon.v1.daemon_pb2 as daemon_proto
import proto.daemon.v1.daemon_pb2_grpc as daemon_grpc


class Daemon:

    def __init__(self, daemon_addr: str):
        self.channel = grpc.insecure_channel(daemon_addr)
        self.daemon = daemon_grpc.DaemonServiceStub(self.channel)
        self.local_ia, core, mtu = self.get_local_as_info()

    def close(self):
        self.channel.close()

    def get_local_as_info(self) -> Tuple[int, bool, int]:
        request = daemon_proto.ASRequest(isd_as=0)
        response = self.daemon.AS(request)
        return response.isd_as, response.core, response.mtu

    def get_paths(self, dst_ia: int):
        request = daemon_proto.PathsRequest(
            source_isd_as=self.local_ia,
            destination_isd_as=dst_ia,
            refresh = False,
            hidden = False)

        response = self.daemon.Paths(request)

        for path in response.paths:
            yield (path.raw, path.interface.address.address)


if __name__ == "__main__":
    daemon = Daemon("10.128.0.2:30255")
    destinations = [0x1ff0000000110, 0x1ff0000000111, 0x1ff0000000112]
    paths = {dest: list(daemon.get_paths(dest)) for dest in destinations}
    print(paths)
