"""Security helpers shared by network-facing components."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class UnsafeURLError(ValueError):
    """Raised when a configured outbound URL is not safe to call."""


# Every placeholder spelling that has ever shipped in this repo's examples,
# CI config, or docs. A secret matching any of these is publicly known and
# therefore forgeable — startup must refuse it (P0-2 / T1-1).
WEAK_SECRET_DENYLIST = frozenset({
    "change-me-in-production",
    "change_me_in_production",
    "changeme",
    "change-me",
    "secret",
    "password",
    "default",
    "ci-jwt-secret-change-me",
})


def assert_strong_secret(name: str, value: str, *, min_len: int = 16) -> None:
    """Refuse startup when a secret is unset, published, or too short.

    Shared by the API factory and the dashboard so every spelling of the
    repo's placeholder secrets is rejected by both services.
    """
    if not value or value.lower() in WEAK_SECRET_DENYLIST or len(value) < min_len:
        raise RuntimeError(
            f"{name} is unset, a published default, or shorter than {min_len} "
            f"chars; generate one with: python -c "
            f"\"import secrets; print(secrets.token_urlsafe(32))\""
        )


def _literal_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _is_localhost_name(hostname: str) -> bool:
    return hostname.lower().rstrip(".") == "localhost"


def _is_loopback_host(hostname: str) -> bool:
    ip = _literal_ip(hostname)
    return bool(ip and ip.is_loopback) or _is_localhost_name(hostname)


def validate_http_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_http_localhost: bool = False,
    allow_private: bool = False,
    context: str = "URL",
) -> str:
    """Validate an outbound HTTP(S) URL before urllib/http clients use it.

    Defaults are intentionally strict: HTTPS only, no literal private/link-local
    IP targets. Local development can opt into loopback HTTP without permitting
    arbitrary private-network or metadata-service access.
    """

    raw = (url or "").strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeURLError(f"{context} must use http or https")
    if not parsed.hostname:
        raise UnsafeURLError(f"{context} must include a hostname")

    host = parsed.hostname.strip("[]")
    is_loopback = _is_loopback_host(host)
    ip = _literal_ip(host)
    if ip and not (allow_private or (allow_http_localhost and ip.is_loopback)):
        if (
            ip.is_private
            or ip.is_link_local
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise UnsafeURLError(f"{context} may not target private or local IPs")
    if _is_localhost_name(host) and not allow_http_localhost:
        raise UnsafeURLError(f"{context} may not target localhost")

    if scheme == "http" and not (allow_http or (allow_http_localhost and is_loopback)):
        raise UnsafeURLError(f"{context} must use https outside localhost")
    return raw


def validate_urllib_request(req, **kwargs) -> None:
    """Validate a urllib Request or URL string before opening it."""

    url = getattr(req, "full_url", req)
    validate_http_url(str(url), **kwargs)
