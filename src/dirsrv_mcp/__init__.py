"""389 Directory Server MCP helpers."""

__all__ = ["DirSrvMCP"]


def __getattr__(name: str):
    if name == "DirSrvMCP":
        # Lazy import to avoid circular import when config loader references
        # connection helpers before the server module is ready.
        from .server import DirSrvMCP  # type: ignore

        return DirSrvMCP
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

