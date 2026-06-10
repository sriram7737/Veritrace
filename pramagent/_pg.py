"""
pramagent._pg
=============
Postgres driver shim. The packaged extra is ``psycopg[binary]`` (psycopg 3 —
the maintained driver; psycopg2-binary is explicitly not recommended for
production by its maintainers), but existing deployments that already have
psycopg2 installed keep working: ``connect()`` prefers psycopg 3 and falls
back to psycopg2.

Both drivers expose the same surface used in this codebase: ``connect(dsn)``,
``%s`` placeholders, cursor context managers, ``commit``/``rollback``/
``close``, and the connection context manager (transaction scope).
"""
from __future__ import annotations


def driver():
    """Return (name, module) for the available driver, or (None, None)."""
    try:
        import psycopg  # psycopg 3
        return "psycopg3", psycopg
    except ImportError:
        pass
    try:
        import psycopg2
        return "psycopg2", psycopg2
    except ImportError:
        return None, None


def connect(dsn: str):
    """Open a connection with whichever driver is installed.

    Raises RuntimeError with an install hint when neither is available.
    """
    name, mod = driver()
    if mod is None:
        raise RuntimeError(
            "no Postgres driver installed; install pramagent[postgres] "
            "(psycopg[binary]>=3.1)"
        )
    return mod.connect(dsn)


def transient_exceptions() -> tuple[type, ...]:
    """Exception classes worth retrying (connection blips, timeouts)."""
    name, mod = driver()
    if mod is None:
        return ()
    return (mod.OperationalError, mod.InterfaceError)
