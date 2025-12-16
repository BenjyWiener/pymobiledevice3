import logging
from typing import Optional
from typing_extensions import Self

from pymobiledevice3.exceptions import ServiceNotConnectedError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.remotexpc import RemoteXPCConnection


class RemoteService:
    def __init__(self, rsd: RemoteServiceDiscoveryService, service_name: str) -> None:
        self.service_name: str = service_name
        self.rsd: RemoteServiceDiscoveryService = rsd
        self._service: Optional[RemoteXPCConnection] = None
        self.logger: logging.Logger = logging.getLogger(self.__module__)

    @property
    def service(self) -> RemoteXPCConnection:
        if self._service is None:
            raise ServiceNotConnectedError
        return self._service

    async def connect(self) -> None:
        self._service = self.rsd.start_remote_service(self.service_name)
        await self._service.connect()

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        await self.close()

    async def close(self) -> None:
        if self._service is not None:
            await self._service.close()
