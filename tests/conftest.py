"""Shared test configuration.

The API factory refuses to boot without a persistent store (P0-1). Tests run
against in-memory stores deliberately, so the suite opts in explicitly —
exactly the switch a dev deployment would flip.
"""
import os

os.environ.setdefault("PRAMAGENT_ALLOW_MEMORY_STORE", "1")
