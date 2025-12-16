from dataclasses import dataclass
from typing import Optional

from construct import Array, Bytes, Const, Default, Int32ub, Int32ul, Pointer, this
from construct_typed import DataclassMixin, DataclassStruct, csfield


@dataclass
class FtabEntry(DataclassMixin):
    tag: bytes = csfield(Bytes(4))
    offset: int = csfield(Int32ul)
    size: int = csfield(Int32ul)
    pad_0x0C: int = csfield(Default(Int32ul, 0))
    data: bytes = csfield(Pointer(this.offset, Bytes(this.size)))


@dataclass
class FtabHeader(DataclassMixin):
    always_01: int = csfield(Int32ul)  # 1
    always_ff: int = csfield(Int32ul)  # 0xFFFFFFFF
    unk_0x08: int = csfield(Int32ub)  # 0
    unk_0x0C: int = csfield(Int32ub)  # 0
    unk_0x10: int = csfield(Int32ub)  # 0
    unk_0x14: int = csfield(Int32ub)  # 0
    unk_0x18: int = csfield(Int32ub)  # 0
    unk_0x1C: int = csfield(Int32ub)  # 0
    tag: bytes = csfield(Bytes(4))  # e.g. 'rkos'
    magic: bytes = csfield(Const(b"ftab"))  # 'ftab' magic
    num_entries: int = csfield(Int32ul)
    pad_0x2C: int = csfield(Int32ub)
    entries: list[FtabEntry] = csfield(Array(this.num_entries, DataclassStruct(FtabEntry)))


ftab_header = DataclassStruct(FtabHeader)


class Ftab:
    def __init__(self, component_data: bytes) -> None:
        self.parsed: FtabHeader = ftab_header.parse(component_data)

    @property
    def tag(self) -> bytes:
        return self.parsed.tag

    def get_entry_data(self, tag: bytes) -> Optional[bytes]:
        for entry in self.parsed.entries:
            if entry.tag == tag:
                return entry.data
        return None

    def add_entry(self, tag: bytes, data: bytes) -> None:
        new_offset = self.parsed.entries[-1].offset + self.parsed.entries[-1].size
        new_entry = FtabEntry(tag=tag, offset=new_offset, size=len(data), data=data)

        self.parsed.num_entries += 1
        self.parsed.entries.append(new_entry)

    @property
    def data(self) -> bytes:
        return ftab_header.build(self.parsed)
