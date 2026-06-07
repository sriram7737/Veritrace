import pytest

from pramagent.security import UnsafeURLError, validate_http_url


def test_validate_http_url_allows_https_public_url():
    assert validate_http_url("https://api.example.com/hook") == "https://api.example.com/hook"


def test_validate_http_url_rejects_non_http_schemes():
    with pytest.raises(UnsafeURLError):
        validate_http_url("file:///etc/passwd")


def test_validate_http_url_rejects_metadata_ip():
    with pytest.raises(UnsafeURLError):
        validate_http_url("http://169.254.169.254/latest/meta-data/")


def test_validate_http_url_allows_loopback_http_when_explicit():
    assert (
        validate_http_url(
            "http://127.0.0.1:8001/v1",
            allow_http_localhost=True,
        )
        == "http://127.0.0.1:8001/v1"
    )


def test_validate_http_url_rejects_public_http_by_default():
    with pytest.raises(UnsafeURLError):
        validate_http_url("http://api.example.com/hook")
