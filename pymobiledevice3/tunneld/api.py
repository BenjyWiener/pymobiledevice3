from typing import Optional

import requests

from pymobiledevice3.exceptions import TunneldConnectionError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService

TUNNELD_DEFAULT_ADDRESS = ("127.0.0.1", 49151)


async def get_tunneld_devices(
    tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS,
    *,
    proxy_url: Optional[str] = None,
) -> list[RemoteServiceDiscoveryService]:
    tunnels = _list_tunnels(tunneld_address, proxy_url=proxy_url)
    return await _create_rsds_from_tunnels(tunnels, proxy_url=proxy_url)


async def get_tunneld_device_by_udid(
    udid: str,
    tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS,
    *,
    proxy_url: Optional[str] = None,
) -> Optional[RemoteServiceDiscoveryService]:
    tunnels = _list_tunnels(tunneld_address, proxy_url=proxy_url)
    if udid not in tunnels:
        return None
    rsds = await _create_rsds_from_tunnels({udid: tunnels[udid]}, proxy_url=proxy_url)
    return rsds[0]


def _list_tunnels(
    tunneld_address: tuple[str, int] = TUNNELD_DEFAULT_ADDRESS,
    *,
    proxy_url: Optional[str] = None,
) -> dict[str, list[dict]]:
    try:
        # Get the list of tunnels from the specified address
        proxies = None if proxy_url is None else {"http": proxy_url, "https": proxy_url}
        resp = requests.get(f"http://{tunneld_address[0]}:{tunneld_address[1]}", proxies=proxies)
        tunnels = resp.json()
    except requests.exceptions.ConnectionError as e:
        raise TunneldConnectionError() from e
    return tunnels


async def _create_rsds_from_tunnels(
    tunnels: dict[str, list[dict]], *, proxy_url: Optional[str] = None
) -> list[RemoteServiceDiscoveryService]:
    rsds = []
    for _udid, details in tunnels.items():
        for tunnel_details in details:
            rsd = RemoteServiceDiscoveryService(
                (tunnel_details["tunnel-address"], tunnel_details["tunnel-port"]),
                name=tunnel_details["interface"],
                proxy_url=proxy_url,
            )
            try:
                await rsd.connect()
                rsds.append(rsd)
            except (TimeoutError, ConnectionError):
                continue
    return rsds
