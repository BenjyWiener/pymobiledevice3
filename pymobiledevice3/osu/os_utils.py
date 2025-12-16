import socket
import sys
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import TypeVar, Union
from typing_extensions import Concatenate, ParamSpec

from pymobiledevice3.exceptions import FeatureNotSupportedError, OSNotSupportedError

DEFAULT_AFTER_IDLE_SEC = 3
DEFAULT_INTERVAL_SEC = 3
DEFAULT_MAX_FAILS = 3


def is_wsl() -> bool:
    try:
        with open("/proc/version") as f:
            version_info = f.read()
            return "Microsoft" in version_info or "WSL" in version_info
    except FileNotFoundError:
        return False


_P = ParamSpec("_P")
_T = TypeVar("_T")


def _default_unsupported(f: "Callable[Concatenate[OsUtils, _P], _T]") -> "Callable[Concatenate[OsUtils, _P], _T]":
    @wraps(f)
    def wrapper(self: OsUtils, *args: _P.args, **kwargs: _P.kwargs) -> _T:
        raise FeatureNotSupportedError(sys.platform, f.__name__)

    return wrapper


class OsUtils:
    _instance = None

    @classmethod
    def create(cls) -> "OsUtils":
        if cls._instance is None:
            if sys.platform == "win32":
                from pymobiledevice3.osu.win_util import Win32

                cls._instance = Win32()
            elif sys.platform == "darwin":
                from pymobiledevice3.osu.posix_util import Darwin

                cls._instance = Darwin()
            elif sys.platform == "linux":
                from pymobiledevice3.osu.posix_util import Linux, Wsl

                cls._instance = Wsl() if is_wsl() else Linux()
            elif sys.platform == "cygwin":
                from pymobiledevice3.osu.posix_util import Cygwin

                cls._instance = Cygwin()
            else:
                raise OSNotSupportedError(sys.platform)
        return cls._instance

    @property
    @_default_unsupported
    def is_admin(self) -> bool: ...

    @property
    @_default_unsupported
    def usbmux_address(self) -> tuple[Union[tuple, str], socket.AddressFamily]: ...

    @property
    @_default_unsupported
    def bonjour_timeout(self) -> int: ...

    @property
    @_default_unsupported
    def loopback_header(self) -> bytes: ...

    @property
    @_default_unsupported
    def access_denied_error(self) -> str: ...

    @property
    @_default_unsupported
    def pair_record_path(self) -> Path: ...

    @_default_unsupported
    def get_ipv6_ips(self) -> list[str]: ...

    @_default_unsupported
    def set_keepalive(
        self,
        sock: socket.socket,
        after_idle_sec: int = DEFAULT_AFTER_IDLE_SEC,
        interval_sec: int = DEFAULT_INTERVAL_SEC,
        max_fails: int = DEFAULT_MAX_FAILS,
    ) -> None: ...

    @_default_unsupported
    def parse_timestamp(self, time_stamp: float) -> datetime: ...

    @_default_unsupported
    def chown_to_non_sudo_if_needed(self, path: Path) -> None: ...

    @_default_unsupported
    def wait_return(self) -> None: ...

    def get_homedir(self) -> Path:
        return Path.home()


def get_os_utils() -> OsUtils:
    return OsUtils.create()
