from typing import Optional

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.lockdown_service import LockdownService

SRCFILES = """Baseband
CrashReporter
MobileAsset
VARFS
HFSMeta
Lockdown
MobileBackup
MobileDelete
MobileInstallation
MobileNotes
Network
UserDatabases
WiFi
WirelessAutomation
NANDDebugInfo
SystemConfiguration
Ubiquity
tmp
WirelessAutomation"""


class FileRelayService(LockdownService):
    SERVICE_NAME = "com.apple.mobile.file_relay"

    def __init__(self, lockdown: LockdownClient) -> None:
        super().__init__(lockdown, self.SERVICE_NAME)
        self.packet_num = 0

    def stop_session(self) -> None:
        self.logger.info("Disconecting...")
        self.service.close()

    def request_sources(self, sources: Optional[list[str]] = None) -> Optional[bytes]:
        if sources is None:
            sources = ["UserDatabases"]
        self.service.send_plist({"Sources": sources})
        while True:
            res = self.service.recv_plist()
            if res:
                status = res.get("Status")
                if status == "Acknowledged":
                    return b"".join(iter(self.service.recv, b""))
                else:
                    print(res.get("Error"))
                    break
        return None
