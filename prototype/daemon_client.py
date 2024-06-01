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

from typing import Optional

import grpc
import proto.daemon.v1.daemon_pb2 as daemon_proto
import proto.daemon.v1.daemon_pb2_grpc as daemon_grpc


class DaemonClient:

    def __init__(self, daemon_addr: str):
        self.channel = grpc.insecure_channel(daemon_addr)
        self.daemon = daemon_grpc.DaemonServiceStub(self.channel)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self.channel.close()

    def rpc_as(self, isd_as: Optional[int]) -> daemon_proto.ASResponse:
        request = daemon_proto.ASRequest(isd_as=isd_as)
        return self.daemon.AS(request)

    def rpc_paths(self,
                 source: int, destination: int,
                 refresh: bool = False, hidden: bool = False) -> daemon_proto.PathsResponse:
        request = daemon_proto.PathsRequest(
            source_isd_as=source,
            destination_isd_as=destination,
            refresh=refresh,
            hidden=hidden)
        return self.daemon.Paths(request)

    def rpc_interfaces(self) -> daemon_proto.InterfacesResponse:
        request = daemon_proto.InterfacesRequest()
        return self.daemon.Interfaces(request)

    def rpc_services(self) -> daemon_proto.ServicesResponse:
        request = daemon_proto.ServicesRequest()
        return self.daemon.Services(request)

    def rpc_notify_interface_down(self, isd_as: int, ifid: int) -> None:
        request = daemon_proto.NotifyInterfaceDownRequest(isd_as = isd_as, id=ifid)
        self.daemon.NotifyInterfaceDown(request)

    def rpc_drkey_as_host(self,
                          val_time, proto: str,
                          src_ia: int, dst_ia: int,
                          dst_host: str) -> daemon_proto.DRKeyASHostResponse:
        request = daemon_proto.DRKeyASHostRequest(
            val_time=val_time,
            protocol_id=proto,
            src_ia=src_ia,
            dst_ia=dst_ia,
            dst_host=dst_host)
        return self.daemon.DRKeyASHost(request)

    def rpc_drkey_host_as(self,
                          val_time, proto: str,
                          src_ia: int, dst_ia: int,
                          src_host: str) -> daemon_proto.DRKeyHostASResponse:
        request = daemon_proto.DRKeyHostASRequest(
            val_time=val_time,
            protocol_id=proto,
            src_ia=src_ia,
            dst_ia=dst_ia,
            src_host=src_host)
        return self.daemon.DRKeyHostAS(request)

    def rpc_drkey_host_host(self,
                          val_time, proto: str,
                          src_ia: int, dst_ia: int,
                          src_host: str, dst_host: str) -> daemon_proto.DRKeyHostHostResponse:
        request = daemon_proto.DRKeyHostHostRequest(
            val_time=val_time,
            protocol_id=proto,
            src_ia=src_ia,
            dst_ia=dst_ia,
            src_host=src_host,
            dst_host=dst_host)
        return self.daemon.DRKeyHostHost(request)
