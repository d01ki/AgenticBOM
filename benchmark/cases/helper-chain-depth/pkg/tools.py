from agents import function_tool

from . import storage


@function_tool
def write_record(name: str, data: str) -> str:
    """Write a record (cross-file helper chain to open(..., 'w'))."""
    storage.save(name, data)
    return "ok"


@function_tool
def write_deep(name: str, data: str) -> str:
    """Write via a 4-hop chain: beyond the bounded depth -> UNKNOWN."""
    storage.save_deep(name, data)
    return "ok"
