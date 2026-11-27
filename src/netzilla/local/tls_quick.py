"""Local TLS inspection with openssl — the instant, offline half of the
SSL/TLS tab. SSL Labs supplies the deep graded assessment; this supplies the
answer in under a second, works against internal hosts, and never leaves the
network.

macOS ships LibreSSL's openssl, which has no -brief; the full report is
shown instead, with the certificate's PEM block left out. Windows has no
openssl at all unless one is installed, and python_probe() gives the same
summary from Python's own TLS stack.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone

from .runner import CommandResult, run

_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def without_pem(text: str) -> str:
    """s_client's full report with the base64 certificate blocks left out."""
    return _PEM_RE.sub("(certificate PEM left out)", text or "")


async def openssl_probe(host: str, port: int = 443, timeout: float = 15.0) -> CommandResult:
    argv = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-brief",
    ]
    # An empty stdin, closed at once: s_client finishes the handshake, prints
    # it, sees end-of-input and hangs up — instead of waiting on the terminal.
    result = await run(argv, timeout=timeout, ok_returncodes=(0, 1), stdin_text="")
    if "unknown option" in f"{result.error}\n{result.output}".lower():
        # LibreSSL (macOS): no -brief. Ask for the full report.
        result = await run(argv[:-1], timeout=timeout, ok_returncodes=(0, 1), stdin_text="")
        if result.output or result.error:
            combined = "\n".join(p for p in (result.output, result.error) if p)
            return CommandResult(True, without_pem(combined), "", result.command)
    if result.output or result.error:
        # openssl writes its handshake summary to stderr with -brief.
        combined = "\n".join(p for p in (result.output, result.error) if p)
        return CommandResult(True, combined, "", result.command)
    return result


def handshake_text(info: dict) -> str:
    """inspect_certificate()'s answer laid out like `openssl s_client -brief`."""
    if info.get("error") and not info.get("protocol"):
        return info["error"]
    lines = [
        f"Protocol version: {info.get('protocol') or '?'}",
        f"Ciphersuite: {info.get('cipher') or '?'}"
        + (f" ({info['cipher_bits']} bits)" if info.get("cipher_bits") else ""),
    ]
    if info.get("subject_cn") or info.get("subject_o"):
        lines.append("Peer certificate: " + ", ".join(
            f"{k}={v}" for k, v in (("CN", info.get("subject_cn")), ("O", info.get("subject_o")))
            if v))
    if info.get("issuer_cn") or info.get("issuer_o"):
        lines.append("Issuer: " + ", ".join(
            f"{k}={v}" for k, v in (("CN", info.get("issuer_cn")), ("O", info.get("issuer_o")))
            if v))
    if info.get("not_after"):
        lines.append(f"Valid until: {info['not_after']}")
    if info.get("sha256_fingerprint"):
        lines.append(f"SHA-256 fingerprint: {info['sha256_fingerprint']}")
    lines.append("Verification: " + ("OK" if info.get("verified") else
                                      info.get("error") or "not verified"))
    return "\n".join(lines)


async def python_probe(host: str, port: int = 443, timeout: float = 10.0) -> CommandResult:
    """OPENSSL HANDSHAKE without openssl: Python's TLS stack's view of it."""
    info = await asyncio.to_thread(inspect_certificate, host, port, timeout)
    return CommandResult(bool(info.get("protocol")), handshake_text(info),
                         "" if info.get("protocol") else info.get("error", ""),
                         f"python ssl {host}:{port}")


def inspect_certificate(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Pull the peer certificate with Python's own TLS stack.

    Runs in a worker thread (see the screen) because ssl is blocking.
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    info: dict = {"host": host, "port": port}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                info["protocol"] = tls.version()
                cipher = tls.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                    info["cipher_bits"] = cipher[2]
                info["verified"] = True
                info.update(_parse_cert(cert))
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["error"] = f"Certificate verification failed: {exc.verify_message or exc}"
        info.update(_unverified_fallback(host, port, timeout))
    except ssl.SSLError as exc:
        info["verified"] = False
        info["error"] = f"TLS error: {exc}"
    except socket.timeout:
        info["error"] = f"Connection to {host}:{port} timed out."
    except OSError as exc:
        info["error"] = f"Could not connect to {host}:{port} — {exc.strerror or exc}"
    return info


def _unverified_fallback(host: str, port: int, timeout: float) -> dict:
    """Report what we can when chain verification fails.

    A failed verification is the interesting case, not a reason to show
    nothing — self-signed internal certs land here constantly. Python's ssl
    module will not parse the certificate fields of an unverified peer
    through any public API, so rather than reaching into CPython internals
    this returns the details that *are* publicly available: the negotiated
    protocol and cipher, and the SHA-256 fingerprint, which is exactly what
    you compare against a known-good value for a self-signed cert.
    """
    context = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                out: dict = {"protocol": tls.version()}
                cipher = tls.cipher()
                if cipher:
                    out["cipher"] = cipher[0]
                    out["cipher_bits"] = cipher[2]
                der = tls.getpeercert(binary_form=True)
                if der:
                    digest = hashlib.sha256(der).hexdigest().upper()
                    out["sha256_fingerprint"] = ":".join(
                        digest[i:i + 2] for i in range(0, len(digest), 2)
                    )
                    out["certificate_bytes"] = len(der)
                    out["pem_available"] = True
                return out
    except Exception:
        return {}


def _parse_cert(cert: dict | None) -> dict:
    if not cert:
        return {}
    subject = _flatten_name(cert.get("subject"))
    issuer = _flatten_name(cert.get("issuer"))
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    out: dict = {
        "subject_cn": subject.get("commonName"),
        "subject_o": subject.get("organizationName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_o": issuer.get("organizationName"),
        "serial": cert.get("serialNumber"),
        "not_before": not_before,
        "not_after": not_after,
        "sans": [v for k, v in (cert.get("subjectAltName") or ()) if k == "DNS"],
    }
    expiry = _parse_date(not_after)
    if expiry:
        remaining = (expiry - datetime.now(timezone.utc)).days
        out["days_remaining"] = remaining
        out["expired"] = remaining < 0
    return out


def _flatten_name(name) -> dict:
    flat = {}
    for rdn in name or ():
        for key, value in rdn:
            flat[key] = value
    return flat


def _parse_date(value: str | None):
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def expiry_verdict(info: dict) -> tuple[str, str]:
    if info.get("error") and "days_remaining" not in info:
        return info["error"], "bad"
    days = info.get("days_remaining")
    if days is None:
        return "Certificate retrieved, expiry unknown", "info"
    if days < 0:
        return f"EXPIRED {abs(days)} days ago", "bad"
    if days <= 14:
        return f"EXPIRES IN {days} DAYS — renew now", "bad"
    if days <= 30:
        return f"Expires in {days} days", "warn"
    return f"Valid for another {days} days", "ok"
