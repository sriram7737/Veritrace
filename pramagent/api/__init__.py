"""HTTP sidecar for Pramagent. Import the app factory or the ready-made app.

    from pramagent.api.app import app, create_app
"""
from .app import app, create_app

__all__ = ["app", "create_app"]
