"""Power-profile trusted workspace-manager skeleton.

P0 deliberately exposes no workspace or command API. Those contracts begin in
P1 after path, resource, artifact, and lifecycle rules are implemented.
"""

from .app import create_sandboxd_app
from .settings import PowerProfileDisabledError, SandboxdSettings

__all__ = ["PowerProfileDisabledError", "SandboxdSettings", "create_sandboxd_app"]
