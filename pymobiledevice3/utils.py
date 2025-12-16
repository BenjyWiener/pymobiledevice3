import asyncio
import traceback
from collections.abc import Coroutine
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union
from typing_extensions import ParamSpec

import requests
from tqdm import tqdm


def plist_access_path(d: dict, path: tuple, type_: Optional[type] = None, required: bool = False) -> Any:
    curr_val: Any = d
    for component in path:
        curr_val = curr_val.get(component)
        if curr_val is None:
            break

    if type_ is bool and isinstance(curr_val, str):
        if curr_val.lower() not in ("true", "false"):
            raise ValueError()
        curr_val = curr_val.lower() == "true"
    elif type_ is not None and not isinstance(curr_val, type_):
        # wrong type
        curr_val = None

    if curr_val is None and required:
        raise KeyError(f"path: {path} doesn't exist in given plist object")

    return curr_val


def bytes_to_uint(b: bytes) -> int:
    return int.from_bytes(b, "little")


def try_decode(s: bytes) -> Union[str, bytes]:
    try:
        return s.decode("utf8")
    except UnicodeDecodeError:
        return s


_P = ParamSpec("_P")
_T = TypeVar("_T")


def asyncio_print_traceback(f: Callable[_P, Coroutine[None, None, _T]]) -> Callable[_P, Coroutine[None, None, _T]]:
    @wraps(f)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return await f(*args, **kwargs)
        except (Exception, RuntimeError) as e:
            if not isinstance(e, asyncio.CancelledError):
                traceback.print_exc()
            raise

    return wrapper


def get_asyncio_loop() -> asyncio.AbstractEventLoop:
    try:
        loop = asyncio.get_running_loop()
        if loop.is_closed():
            raise RuntimeError("The existing loop is closed.")
    except RuntimeError:
        # This happens when there is no current event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop


def file_download(url: str, outfile: Path, chunk_size: int = 1024) -> None:
    resp = requests.get(url, stream=True)
    total = int(resp.headers.get("content-length", 0))
    with (
        outfile.open("wb") as file,
        tqdm(
            desc=outfile.name,
            total=total,
            unit="iB",
            unit_scale=True,
            unit_divisor=1024,
        ) as bar,
    ):
        for data in resp.iter_content(chunk_size=chunk_size):
            size = file.write(data)
            bar.update(size)
