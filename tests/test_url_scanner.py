from __future__ import annotations

from email.message import Message

import pytest

import url_scanner
from scanner import is_url_target


class FakeResponse:
    def __init__(self, headers: Message, status: int = 200, url: str = "https://www.example.com/"):
        self.headers = headers
        self.status = status
        self._url = url
        self.closed = False

    def geturl(self):
        return self._url

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True


def public_dns(*args, **kwargs):
    return [(2, 1, 6, "", ("93.184.216.34", 443))]


def test_url_report_flags_missing_csp_and_wildcard_cors(monkeypatch):
    headers = Message()
    headers["Strict-Transport-Security"] = "max-age=31536000"
    headers["X-Frame-Options"] = "SAMEORIGIN"
    headers["X-Content-Type-Options"] = "nosniff"
    headers["Referrer-Policy"] = "strict-origin"
    headers["Access-Control-Allow-Origin"] = "*"
    response = FakeResponse(headers)
    monkeypatch.setattr(url_scanner.socket, "getaddrinfo", public_dns)
    monkeypatch.setattr(url_scanner, "_fetch", lambda url, timeout: response)

    report = url_scanner.build_url_report("https://example.com")

    assert report["target_type"] == "url"
    assert report["summary"]["checks"] == 6
    assert report["summary"]["severity_counts"] == {"PASS": 4, "WARNING": 2, "FAIL": 0}
    assert response.closed


def test_url_report_fails_wildcard_credentials_and_weak_cookie(monkeypatch):
    headers = Message()
    for name, value in {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Set-Cookie": "session=redacted; Path=/",
    }.items():
        headers[name] = value
    monkeypatch.setattr(url_scanner.socket, "getaddrinfo", public_dns)
    monkeypatch.setattr(url_scanner, "_fetch", lambda url, timeout: FakeResponse(headers))

    report = url_scanner.build_url_report("https://example.com")

    results = {result["check_name"]: result for result in report["results"]}
    assert results["deployed_cors"]["severity"] == "FAIL"
    assert "redacted" not in results["cookie_flags"]["message"]
    assert "session" in results["cookie_flags"]["message"]


def test_url_target_validation_rejects_localhost():
    with pytest.raises(ValueError, match="Localhost"):
        url_scanner.build_url_report("http://localhost:3000")


def test_target_detection_requires_http_scheme():
    assert is_url_target("https://example.com")
    assert not is_url_target("example.com")
