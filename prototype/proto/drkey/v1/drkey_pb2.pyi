from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from typing import ClassVar as _ClassVar

DESCRIPTOR: _descriptor.FileDescriptor

class Protocol(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROTOCOL_GENERIC_UNSPECIFIED: _ClassVar[Protocol]
    PROTOCOL_SCMP: _ClassVar[Protocol]
PROTOCOL_GENERIC_UNSPECIFIED: Protocol
PROTOCOL_SCMP: Protocol
