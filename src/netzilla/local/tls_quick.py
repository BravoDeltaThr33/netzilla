"""Local TLS inspection with openssl — the instant, offline half of the
SSL/TLS tab. SSL Labs supplies the deep graded assessment; this supplies the
answer in under a second, works against internal hosts, and never leaves the
network.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone

from .runner import CommandResult, run


async def openssl_probe(host: str, port: int = 443, timeout: float = 15.0) -> CommandResult:
    argv = [
        "openssl", "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-brief",
    ]
    result = await run(argv, timeout=timeout, ok_returncodes=(0, 1))
    if result.output or result.error:
        # openssl writes its handshake summary to stderr with -brief.
        combined = "\n".join(p for p in (result.output, result.error) if p)
        return CommandResult(True, combined, "", result.command)
    return result


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
