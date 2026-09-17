"""web.tls — transport security: HTTPS presence, certificate, weak protocols.

Read-only handshakes only; sends no application payloads. Maps to OWASP
A04:2025 Cryptographic Failures. The socket work is stdlib ssl; it never raises
out of scan() — a failed handshake becomes a finding or is skipped, never a crash.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ...core.engine import register
from ...core.finding import Finding
from ...core.target import TargetKind
from . import http

_CAT = "A04:2025 Cryptographic Failures"
_REFS = ["https://cheatsheetseries.owasp.org/cheatsheets/"
         "Transport_Layer_Security_Cheat_Sheet.html"]

# Legacy protocols that should no longer be accepted.
_WEAK_PROTOCOLS = [("TLSv1.0", ssl.TLSVersion.TLSv1),
                   ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]


def _peer_cert(host: str, port: int, timeout: float):
    """Return the validated peer certificate dict, or None if it can't be got."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def _weak_protocol_accepted(host: str, port: int, version, timeout: float) -> bool:
    """True if the server completes a handshake pinned to a legacy protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
        return False                    # this Python build can't offer that version
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


@register(TargetKind.WEB, "web.tls")
def scan(target, ctx):
    url = target.location
    parts = urlparse(url)
    host = parts.hostname or ""
    where = f"{parts.scheme}://{parts.netloc}"

    # 1. No HTTPS at all — everything travels in clear text.
    if parts.scheme != "https":
        port = parts.port or 80
        https_url = "https://" + parts.netloc + (parts.path or "")
        upgrade = http.fetch(https_url, timeout=ctx.timeout)
        redirects = upgrade.ok and upgrade.final_url.lower().startswith("https")
        yield Finding(
            title="Site served over HTTP (no TLS)", severity="high", where=where,
            scanner="web.tls",
            what="The site is reachable over plain HTTP, so credentials and data "
                 "travel unencrypted and can be read or altered in transit.",
            how_to_check=f"Open {where} and confirm the browser shows 'Not secure' "
                         "with no padlock.",
            evidence=("An HTTPS version exists but HTTP is still served."
                      if redirects else "No working HTTPS endpoint responded."),
            remediation="Serve everything over HTTPS and 301-redirect HTTP to HTTPS; "
                        "then add HSTS.",
            category=_CAT, references=_REFS,
        )
        return                          # cert / protocol checks below need TLS

    port = parts.port or 443

    # 2. Certificate: reachable + not expired.
    cert = _peer_cert(host, port, ctx.timeout)
    if cert is None:
        yield Finding(
            title="TLS certificate could not be validated", severity="high",
            where=where, scanner="web.tls",
            what="The certificate failed validation (untrusted, self-signed, "
                 "hostname mismatch, or expired). Browsers will warn or block.",
            how_to_check=f"Run: openssl s_client -connect {host}:{port} -servername {host}",
            remediation="Install a certificate from a trusted CA that matches the "
                        "hostname and is within its validity window.",
            category=_CAT, references=_REFS,
        )
    else:
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    yield Finding(
                        title="TLS certificate has expired", severity="high",
                        where=where, scanner="web.tls",
                        what="The certificate expired; browsers will refuse the "
                             "connection or warn users away.",
                        how_to_check=f"openssl s_client -connect {host}:{port} shows "
                                     "notAfter in the past.",
                        evidence=f"notAfter: {not_after}",
                        remediation="Renew and redeploy the certificate; automate "
                                    "renewal (e.g. ACME/Let's Encrypt).",
                        category=_CAT, references=_REFS)
                elif days < 21:
                    yield Finding(
                        title=f"TLS certificate expires in {days} days",
                        severity="low", where=where, scanner="web.tls",
                        what="The certificate is close to expiry; if it lapses the "
                             "site becomes unreachable.",
                        how_to_check="Check the certificate's notAfter date.",
                        evidence=f"notAfter: {not_after}",
                        remediation="Renew now and automate future renewals.",
                        category=_CAT, references=_REFS)
            except ValueError:
                pass                    # unparseable date — skip rather than guess

    # 3. Legacy protocols still accepted.
    for name, version in _WEAK_PROTOCOLS:
        if _weak_protocol_accepted(host, port, version, ctx.timeout):
            yield Finding(
                title=f"Weak TLS protocol {name} accepted", severity="medium",
                where=where, scanner="web.tls",
                what=f"The server completes a handshake using {name}, a legacy "
                     "protocol with known weaknesses that should be disabled.",
                how_to_check=f"openssl s_client -connect {host}:{port} "
                             f"-{name.lower().replace('v', '').replace('.', '_')}",
                evidence=f"Handshake succeeded pinned to {name}.",
                remediation="Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
                category=_CAT, references=_REFS)


def demo() -> None:
    from types import SimpleNamespace

    ctx = SimpleNamespace(cache={}, timeout=5.0, aggressive=False, only=set())

    # HTTP target with no HTTPS reachable -> one high 'no TLS' finding, offline
    # (127.0.0.1:9 is the discard port; the HTTPS upgrade probe just fails fast).
    target = SimpleNamespace(location="http://127.0.0.1:9/", kind=TargetKind.WEB)
    found = list(scan(target, ctx))
    assert len(found) == 1 and found[0].severity.label == "High", found
    assert "HTTP" in found[0].title and found[0].remediation
    print("tls.py: ok")


if __name__ == "__main__":
    demo()
