#!/bin/bash

python3 -m grpc_tools.protoc --python_out=. --pyi_out=. --grpc_python_out=. \
    -I . proto/daemon/v1/daemon.proto

python3 -m grpc_tools.protoc --python_out=. --pyi_out=. --grpc_python_out=. \
    -I . proto/drkey/v1/drkey.proto
