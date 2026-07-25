"""Non-invasive HTTP security checks for a deployed website."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass
from enum import Enum
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

URL_CHECK_COUNT = 6
DEFAULT_TIMEOUT_SECONDS = 15


class Severity(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass(frozen=True)
class UrlCheckResult:
    check_name: str
    severity: Severity
    message: str

    def to_dict(self) -> dict:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


def _normalize_url(url: str) -> str:
    value = url.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL targets must include http:// or https:// and a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported.")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost URL targets are not supported.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve URL hostname: {error}") from error
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("URL target must resolve only to public IP addresses.")
    return value


class SafeRedirectHandler(HTTPRedirectHandler):
    """Follow modern redirects while rejecting non-public destinations."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _normalize_url(newurl)
        compatible_code = 307 if code == 308 else code
        return super().redirect_request(req, fp, compatible_code, msg, headers, newurl)

    http_error_308 = HTTPRedirectHandler.http_error_302


def _fetch(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS):
    request = Request(
        url,
        headers={
            "User-Agent": "vibe-scanner/1.0 (+read-only security check)",
            "Origin": "https://vibe-scanner.invalid",
            "Accept": "text/html,application/xhtml+xml",
        },
        method="GET",
    )
    try:
        return build_opener(SafeRedirectHandler()).open(request, timeout=timeout)
    except HTTPError as error:
        return error
    except (URLError, TimeoutError, ssl.SSLError, OSError) as error:
        raise RuntimeError(f"Could not reach target: {error}") from error


def _cookie_name(raw_cookie: str) -> str:
    first = raw_cookie.split(";", 1)[0]
    return first.split("=", 1)[0].strip() or "unnamed cookie"


def build_url_report(
    url: str,
    scanner_version: str = "1.0.0",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Fetch one public page and evaluate response metadata without crawling."""
    requested_url = _normalize_url(url)
    response = _fetch(requested_url, timeout=timeout)
    try:
        final_url = response.geturl()
        status = getattr(response, "status", None) or response.getcode()
        headers = response.headers
    finally:
        response.close()
    results: list[UrlCheckResult] = []

    status_severity = Severity.PASS if 200 <= status < 400 else Severity.WARNING
    results.append(
        UrlCheckResult(
            "http_reachability",
            status_severity,
            f"Target responded with HTTP {status}.",
        )
    )

    if urlparse(final_url).scheme == "https":
        results.append(
            UrlCheckResult(
                "https_transport",
                Severity.PASS,
                "Final response uses HTTPS.",
            )
        )
    else:
        results.append(
            UrlCheckResult(
                "https_transport",
                Severity.FAIL,
                "Final response is served without HTTPS.",
            )
        )

    required_headers = {
        "Content-Security-Policy": "content-security-policy",
        "Frame protection": "x-frame-options",
        "X-Content-Type-Options": "x-content-type-options",
        "Referrer-Policy": "referrer-policy",
        "Strict-Transport-Security": "strict-transport-security",
    }
    missing = []
    for label, header in required_headers.items():
        content_security_policy = headers.get("Content-Security-Policy", "").lower()
        if header == "x-frame-options" and "frame-ancestors" in content_security_policy:
            continue
        if not headers.get(header):
            missing.append(label)
    if missing:
        results.append(
            UrlCheckResult(
                "deployed_security_headers",
                Severity.WARNING,
                f"Missing deployed security headers: {', '.join(missing)}.",
            )
        )
    else:
        results.append(
            UrlCheckResult(
                "deployed_security_headers",
                Severity.PASS,
                "Baseline deployed security headers are present.",
            )
        )

    allow_origin = headers.get("Access-Control-Allow-Origin", "").strip()
    allow_credentials = (
        headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
    )
    if allow_origin == "*" and allow_credentials:
        results.append(
            UrlCheckResult(
                "deployed_cors",
                Severity.FAIL,
                "Wildcard CORS is combined with credentialed requests.",
            )
        )
    elif allow_origin == "*":
        results.append(
            UrlCheckResult(
                "deployed_cors",
                Severity.WARNING,
                "Response permits requests from every origin; confirm this is intentional.",
            )
        )
    else:
        results.append(
            UrlCheckResult(
                "deployed_cors",
                Severity.PASS,
                "No wildcard CORS response was observed.",
            )
        )

    cookies = headers.get_all("Set-Cookie", [])
    weak_cookies = []
    for cookie in cookies:
        lower = cookie.lower()
        missing_flags = [
            flag for flag in ("Secure", "HttpOnly", "SameSite") if flag.lower() not in lower
        ]
        if missing_flags:
            weak_cookies.append(f"{_cookie_name(cookie)} missing {'/'.join(missing_flags)}")
    if weak_cookies:
        results.append(
            UrlCheckResult(
                "cookie_flags",
                Severity.WARNING,
                "Cookie hardening issue(s): " + "; ".join(weak_cookies) + ".",
            )
        )
    else:
        if cookies:
            message = "Observed cookies include Secure, HttpOnly, and SameSite attributes."
        else:
            message = "No cookies were set by the scanned page."
        results.append(UrlCheckResult("cookie_flags", Severity.PASS, message))

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        results.append(
            UrlCheckResult(
                "technology_disclosure",
                Severity.WARNING,
                "X-Powered-By reveals the application technology.",
            )
        )
    else:
        results.append(
            UrlCheckResult(
                "technology_disclosure",
                Severity.PASS,
                "No X-Powered-By technology disclosure observed.",
            )
        )

    counts = {
        severity.value: sum(result.severity == severity for result in results)
        for severity in Severity
    }
    return {
        "scanner_version": scanner_version,
        "target_type": "url",
        "target": requested_url,
        "final_url": final_url,
        "summary": {
            "checks": URL_CHECK_COUNT,
            "findings": counts["WARNING"] + counts["FAIL"],
            "severity_counts": counts,
        },
        "results": [result.to_dict() for result in results],
    }
