"""HTTP sidecar for Veritrace. Import the app factory or the ready-made app.

    from veritrace.api.app import app, create_app
"""
from .app import app, create_app

__all__ = ["app", "create_app"]
