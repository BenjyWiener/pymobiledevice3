import dataclasses
import uuid
from datetime import datetime
from functools import singledispatch
from typing import Any, Optional, Union

from construct import (
    Aligned,
    Array,
    Bytes,
    Const,
    CString,
    Default,
    Double,
    Error,
    ExprAdapter,
    GreedyBytes,
    Hex,
    If,
    Int32ul,
    Int64sl,
    Int64ul,
    LazyBound,
    Pass,
    Prefixed,
    Probe,
    Switch,
    obj_,
    this,
)
from construct import Optional as ConstructOptional
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, FlagsEnumBase, TEnum, TFlagsEnum, csfield


class XpcMessageType(EnumBase):
    NULL = 0x00001000
    BOOL = 0x00002000
    INT64 = 0x00003000
    UINT64 = 0x00004000
    DOUBLE = 0x00005000
    POINTER = 0x00006000
    DATE = 0x00007000
    DATA = 0x00008000
    STRING = 0x00009000
    UUID = 0x0000A000
    FD = 0x0000B000
    SHMEM = 0x0000C000
    MACH_SEND = 0x0000D000
    ARRAY = 0x0000E000
    DICTIONARY = 0x0000F000
    ERROR = 0x00010000
    CONNECTION = 0x00011000
    ENDPOINT = 0x00012000
    SERIALIZER = 0x00013000
    PIPE = 0x00014000
    MACH_RECV = 0x00015000
    BUNDLE = 0x00016000
    SERVICE = 0x00017000
    SERVICE_INSTANCE = 0x00018000
    ACTIVITY = 0x00019000
    FILE_TRANSFER = 0x0001A000


class XpcFlags(FlagsEnumBase):
    ALWAYS_SET = 0x00000001
    PING = 0x00000002
    DATA_PRESENT = 0x00000100
    WANTING_REPLY = 0x00010000
    REPLY = 0x00020000
    FILE_TX_STREAM_REQUEST = 0x00100000
    FILE_TX_STREAM_RESPONSE = 0x00200000
    INIT_HANDSHAKE = 0x00400000


AlignedString = Aligned(4, CString("utf8"))
XpcNull = Pass
XpcBool = Int32ul
XpcInt64 = Int64sl
XpcUInt64 = Int64ul
XpcDouble = Double
XpcPointer = Error
XpcDate = Int64ul
XpcData = Aligned(4, Prefixed(Int32ul, GreedyBytes))
XpcString = Aligned(4, Prefixed(Int32ul, CString("utf8")))
XpcUuid = Bytes(16)
XpcFd = Int32ul


@dataclasses.dataclass
class XpcShmem(DataclassMixin):
    length: int = csfield(Int32ul)
    _: int = csfield(Int32ul)


@dataclasses.dataclass
class XpcArray(DataclassMixin):
    count: int = csfield(Int32ul)
    entries: "list[XpcObject]" = csfield(Array(this.count, LazyBound(lambda: DataclassStruct(XpcObject))))


@dataclasses.dataclass
class XpcDictionaryEntry(DataclassMixin):
    key: str = csfield(AlignedString)
    value: "XpcObject" = csfield(LazyBound(lambda: DataclassStruct(XpcObject)))


@dataclasses.dataclass
class XpcDictionary(DataclassMixin):
    count: int = csfield(Hex(Int32ul))
    entries: Optional[list[XpcDictionaryEntry]] = csfield(
        If(this.count > 0, Array(this.count, DataclassStruct(XpcDictionaryEntry)))
    )


@dataclasses.dataclass
class XpcFileTransfer(DataclassMixin):
    msg_id: int = csfield(Int64ul)
    data: "XpcObject" = csfield(LazyBound(lambda: DataclassStruct(XpcObject)))


XpcObjectDataType = Union[
    XpcDictionary,
    str,
    float,
    None,
    bytes,
    bytearray,
    XpcShmem,
    XpcArray,
    XpcFileTransfer,
]


@dataclasses.dataclass
class XpcObject(DataclassMixin):
    type: XpcMessageType = csfield(TEnum(Hex(Int32ul), XpcMessageType))
    data: XpcObjectDataType = csfield(
        Switch(
            this.type,
            {
                XpcMessageType.DICTIONARY: Prefixed(Int32ul, DataclassStruct(XpcDictionary)),
                XpcMessageType.STRING: XpcString,
                XpcMessageType.INT64: XpcInt64,
                XpcMessageType.UINT64: XpcUInt64,
                XpcMessageType.DOUBLE: XpcDouble,
                XpcMessageType.BOOL: XpcBool,
                XpcMessageType.NULL: XpcNull,
                XpcMessageType.UUID: XpcUuid,
                XpcMessageType.POINTER: XpcPointer,
                XpcMessageType.DATE: XpcDate,
                XpcMessageType.DATA: XpcData,
                XpcMessageType.FD: XpcFd,
                XpcMessageType.SHMEM: DataclassStruct(XpcShmem),
                XpcMessageType.ARRAY: Prefixed(Int32ul, DataclassStruct(XpcArray)),
                XpcMessageType.FILE_TRANSFER: DataclassStruct(XpcFileTransfer),
            },
            default=Probe(lookahead=1000),
        )
    )


@dataclasses.dataclass
class XpcPayload(DataclassMixin):
    magic: int = csfield(Hex(Const(0x42133742, Int32ul)))
    protocol_version: int = csfield(Hex(Const(0x00000005, Int32ul)))
    obj: XpcObject = csfield(DataclassStruct(XpcObject))


@dataclasses.dataclass
class XpcMessage(DataclassMixin):
    message_id: int = csfield(Hex(Default(Int64ul, 0)))
    payload: Optional[XpcPayload] = csfield(ConstructOptional(DataclassStruct(XpcPayload)))


@dataclasses.dataclass
class XpcWrapper(DataclassMixin):
    magic: int = csfield(Hex(Const(0x29B00B92, Int32ul)))
    flags: XpcFlags = csfield(Default(TFlagsEnum(Hex(Int32ul), XpcFlags), XpcFlags.ALWAYS_SET))
    message: XpcMessage = csfield(
        Prefixed(
            ExprAdapter(Int64ul, obj_ + 8, obj_ - 8),
            DataclassStruct(XpcMessage),
        )
    )


XpcWrapperStruct = DataclassStruct(XpcWrapper)


class XpcInt64Type(int):
    pass


class XpcUInt64Type(int):
    pass


@dataclasses.dataclass
class FileTransferType:
    transfer_size: int


def _decode_xpc_dictionary(xpc_object: XpcObject) -> dict:
    assert isinstance(xpc_object.data, XpcDictionary)
    if xpc_object.data.entries is None:
        return {}
    result = {}
    for entry in xpc_object.data.entries:
        result[entry.key] = decode_xpc_object(entry.value)
    return result


def _decode_xpc_array(xpc_object: XpcObject) -> list:
    assert isinstance(xpc_object.data, XpcArray)
    result = []
    for entry in xpc_object.data.entries:
        result.append(decode_xpc_object(entry))
    return result


def _decode_xpc_bool(xpc_object: XpcObject) -> bool:
    return bool(xpc_object.data)


def _decode_xpc_int64(xpc_object: XpcObject) -> XpcInt64Type:
    assert isinstance(xpc_object.data, int)
    return XpcInt64Type(xpc_object.data)


def _decode_xpc_uint64(xpc_object: XpcObject) -> XpcUInt64Type:
    assert isinstance(xpc_object.data, int)
    return XpcUInt64Type(xpc_object.data)


def _decode_xpc_uuid(xpc_object: XpcObject) -> uuid.UUID:
    assert isinstance(xpc_object.data, bytes)
    return uuid.UUID(bytes=xpc_object.data)


def _decode_xpc_string(xpc_object: XpcObject) -> str:
    assert isinstance(xpc_object.data, str)
    return xpc_object.data


def _decode_xpc_data(xpc_object: XpcObject) -> bytes:
    assert isinstance(xpc_object.data, bytes)
    return xpc_object.data


def _decode_xpc_date(xpc_object: XpcObject) -> datetime:
    assert isinstance(xpc_object.data, int)
    # Convert from nanoseconds to seconds
    return datetime.fromtimestamp(xpc_object.data / 1_000_000_000)


def _decode_xpc_file_transfer(xpc_object: XpcObject) -> FileTransferType:
    assert isinstance(xpc_object.data, XpcFileTransfer)
    return FileTransferType(transfer_size=_decode_xpc_dictionary(xpc_object.data.data)["s"])


def _decode_xpc_double(xpc_object: XpcObject) -> float:
    assert isinstance(xpc_object.data, float)
    return xpc_object.data


def _decode_xpc_null(xpc_object: XpcObject) -> None:
    return None


def decode_xpc_object(xpc_object: XpcObject) -> Any:
    decoders = {
        XpcMessageType.DICTIONARY: _decode_xpc_dictionary,
        XpcMessageType.ARRAY: _decode_xpc_array,
        XpcMessageType.BOOL: _decode_xpc_bool,
        XpcMessageType.INT64: _decode_xpc_int64,
        XpcMessageType.UINT64: _decode_xpc_uint64,
        XpcMessageType.UUID: _decode_xpc_uuid,
        XpcMessageType.STRING: _decode_xpc_string,
        XpcMessageType.DATA: _decode_xpc_data,
        XpcMessageType.DATE: _decode_xpc_date,
        XpcMessageType.FILE_TRANSFER: _decode_xpc_file_transfer,
        XpcMessageType.DOUBLE: _decode_xpc_double,
        XpcMessageType.NULL: _decode_xpc_null,
    }
    decoder = decoders.get(xpc_object.type)
    if decoder is None:
        raise TypeError(f"deserialize error: {xpc_object}")
    return decoder(xpc_object)


@singledispatch
def _build_xpc_object(payload: object) -> XpcObject:
    raise TypeError(f"unrecognized type for: {payload} {type(payload)}")


@_build_xpc_object.register
def _(payload: list) -> XpcObject:
    entries = []
    for entry in payload:
        entry = _build_xpc_object(entry)
        entries.append(entry)
    return XpcObject(
        type=XpcMessageType.ARRAY,
        data=XpcArray(
            count=len(entries),
            entries=entries,
        ),
    )


@_build_xpc_object.register
def _(payload: dict) -> XpcObject:
    entries = [XpcDictionaryEntry(key=key, value=_build_xpc_object(value)) for key, value in payload.items()]
    return XpcObject(
        type=XpcMessageType.DICTIONARY,
        data=XpcDictionary(count=len(entries), entries=entries),
    )


@_build_xpc_object.register
def _(payload: bool) -> XpcObject:
    return XpcObject(type=XpcMessageType.BOOL, data=payload)


@_build_xpc_object.register
def _(payload: str) -> XpcObject:
    return XpcObject(type=XpcMessageType.STRING, data=payload)


@_build_xpc_object.register
def _(payload: Union[bytes, bytearray]) -> XpcObject:
    return XpcObject(type=XpcMessageType.DATA, data=payload)


@_build_xpc_object.register
def _(payload: float) -> XpcObject:
    return XpcObject(type=XpcMessageType.DOUBLE, data=payload)


@_build_xpc_object.register
def _(payload: uuid.UUID) -> XpcObject:
    return XpcObject(type=XpcMessageType.UUID, data=payload.bytes)


@_build_xpc_object.register
def _(payload: None) -> XpcObject:
    return XpcObject(type=XpcMessageType.NULL, data=None)


@_build_xpc_object.register
def _(payload: XpcUInt64Type) -> XpcObject:
    return XpcObject(type=XpcMessageType.UINT64, data=payload)


@_build_xpc_object.register
def _(payload: XpcInt64Type) -> XpcObject:
    return XpcObject(type=XpcMessageType.INT64, data=payload)


def create_xpc_wrapper(d: dict, message_id: int = 0, wanting_reply: bool = False) -> bytes:
    flags = XpcFlags.ALWAYS_SET
    if len(d.keys()) > 0:
        flags |= XpcFlags.DATA_PRESENT
    if wanting_reply:
        flags |= XpcFlags.WANTING_REPLY

    return DataclassStruct(XpcWrapper).build(
        XpcWrapper(
            flags=flags,
            message=XpcMessage(
                message_id=message_id,
                payload=XpcPayload(obj=_build_xpc_object(d)),
            ),
        )
    )
