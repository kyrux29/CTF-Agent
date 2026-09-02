"""Read-only MCP facade for CTFMesh's policy-gated tool runtime."""

from .gateway import create_readonly_mcp_server

__all__ = ["create_readonly_mcp_server"]
