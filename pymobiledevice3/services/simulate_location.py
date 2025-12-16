import struct

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.dvt.instruments.location_simulation_base import LocationSimulationBase
from pymobiledevice3.services.lockdown_service import LockdownService


class DtSimulateLocation(LockdownService, LocationSimulationBase):
    SERVICE_NAME = "com.apple.dt.simulatelocation"

    def __init__(self, lockdown: LockdownClient) -> None:
        LockdownService.__init__(self, lockdown, self.SERVICE_NAME)
        LocationSimulationBase.__init__(self)

    def clear(self) -> None:
        """stop simulation"""
        service = self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        service.sendall(struct.pack(">I", 1))

    def set(self, latitude: float, longitude: float) -> None:
        """stop simulation"""
        service = self.lockdown.start_lockdown_developer_service(self.SERVICE_NAME)
        service.sendall(struct.pack(">I", 0))
        latitude_str = str(latitude).encode()
        longitude_str = str(longitude).encode()
        service.sendall(struct.pack(">I", len(latitude_str)) + latitude_str)
        service.sendall(struct.pack(">I", len(longitude_str)) + longitude_str)
