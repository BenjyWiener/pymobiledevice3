import logging
import struct
from typing import BinaryIO

from pymobiledevice3.exceptions import PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.service_connection import ServiceConnection


class DtFetchSymbols:
    SERVICE_NAME = "com.apple.dt.fetchsymbols"
    MAX_CHUNK = 1024 * 1024 * 10  # 10MB
    CMD_LIST_FILES_PLIST = struct.pack(">I", 0x30303030)
    CMD_GET_FILE = struct.pack(">I", 1)

    def __init__(self, lockdown: LockdownClient) -> None:
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.lockdown: LockdownClient = lockdown

    def list_files(self) -> list[str]:
        service = self._start_command(self.CMD_LIST_FILES_PLIST)
        files = service.recv_plist().get("files")
        service.close()
        return files

    def get_file(self, fileno: int, stream: BinaryIO) -> None:
        service = self._start_command(self.CMD_GET_FILE)
        service.sendall(struct.pack(">I", fileno))

        size = struct.unpack(">Q", service.recvall(8))[0]
        self.logger.debug(f"file size: {size}")

        received = 0
        while received < size:
            buf = service.recv(min(size - received, self.MAX_CHUNK))
            stream.write(buf)
            received += len(buf)
        service.close()

    def _start_command(self, cmd: bytes) -> ServiceConnection:
        service = self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        service.sendall(cmd)

        # receive same command as an ack
        if cmd != service.recvall(len(cmd)):
            raise PyMobileDevice3Exception("bad ack")

        return service
