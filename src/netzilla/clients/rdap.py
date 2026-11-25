"""RDAP — Registration Data Access Protocol, the structured JSON successor to
WHOIS.

Endpoint: GET https://rdap.org/domain/{name}
          GET https://rdap.org/ip/{addr}
          GET https://rdap.org/autnum/{asn}
Auth:     none

rdap.org is a bootstrap/redirector run by the RDAP community: it looks up which
registry (ARIN, RIPE, Verisign, etc.) is authoritative for the object and 302s
to it, so netzilla does not need to carry the IANA bootstrap tables. Because it
follows redirects across registries, answers are structured the same way no
matter who the registrar is — the win over scraping free-text WHOIS.
"""

from __future__ import annotations

from ..cache import TTL
from ..services import ApiResult, Services

BASE = "https://rdap.org"


async def _get(services: Services, kind: str, obj: str) -> ApiResult:
    result = await services.fetch(
        source="rdap",
        url=f"{BASE}/{kind}/{obj}",
        headers={"Accept": "application/rdap+json, application/json"},
        cache_key=f"rdap:{kind}:{obj}",
        ttl=TTL["whois"],
        ok_statuses=(200,),
    )
    if not result.ok:
        if result.status_code == 404:
            return ApiResult.failure(
                "rdap", f"No RDAP record found for {obj}.", status_code=404
            )
        return result
    if not isinstance(result.data, dict):
        return ApiResult.failure("rdap", "RDAP returned an unexpected shape.")
    return ApiResult.success("rdap", result.data, cached=result.cached)


async def domain(services: Services, name: str) -> ApiResult:
    return await _get(services, "domain", name.strip().lower().rstrip("."))


async def ip(services: Services, addr: str) -> ApiResult:
    return await _get(services, "ip", addr.strip())


async def autnum(services: Services, asn: int) -> ApiResult:
    return await _get(services, "autnum", str(asn))


# --------------------------------------------------------------- parsing
def _event(events: list, action: str) -> str:
    for event in events or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            return (event.get("eventDate") or "")[:19].replace("T", " ")
    return ""


def registration_date(payload: dict) -> str:
    return _event(payload.get("events"), "registration")


def _vcard_field(entity: dict, field: str) -> str:
    """Pull one field out of a jCard (vcardArray) inside an RDAP entity."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == field:
            value = item[-1]
            if isinstance(value, list):
                return ", ".join(str(v) for v in value if v)
            return str(value or "")
    return ""


def _roles_text(entity: dict) -> str:
    roles = entity.get("roles") or []
    return ", ".join(roles) if roles else ""


def entities_by_role(payload: dict) -> dict[str, str]:
    """Map each RDAP role (registrar, registrant, abuse, ...) to a display name."""
    out: dict[str, str] = {}
    for entity in payload.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        name = _vcard_field(entity, "fn") or entity.get("handle") or ""
        for role in entity.get("roles") or ["entity"]:
            out.setdefault(role, name)
        # Abuse contact is often nested one level down under the registrar.
        for sub in entity.get("entities") or []:
            if isinstance(sub, dict) and "abuse" in (sub.get("roles") or []):
                email = _vcard_field(sub, "email")
                if email:
                    out["abuse-email"] = email
    return out


def abuse_email(payload: dict) -> str:
    """Best-effort abuse contact email, however deeply nested."""
    def walk(entity: dict) -> str:
        if "abuse" in (entity.get("roles") or []):
            email = _vcard_field(entity, "email")
            if email:
                return email
        for sub in entity.get("entities") or []:
            if isinstance(sub, dict):
                found = walk(sub)
                if found:
                    return found
        return ""

    for entity in payload.get("entities") or []:
        if isinstance(entity, dict):
            found = walk(entity)
            if found:
                return found
    return ""


def domain_summary(payload: dict) -> list[tuple[str, object]]:
    roles = entities_by_role(payload)
    statuses = payload.get("status") or []
    nameservers = [
        ns.get("ldhName") for ns in payload.get("nameservers") or []
        if isinstance(ns, dict) and ns.get("ldhName")
    ]
    return [
        ("Domain", payload.get("ldhName") or payload.get("handle")),
        ("Registered", registration_date(payload)),
        ("Last changed", _event(payload.get("events"), "last changed")),
        ("Expires", _event(payload.get("events"), "expiration")),
        ("Registrar", roles.get("registrar")),
        ("Registrant", roles.get("registrant")),
        ("Abuse contact", abuse_email(payload)),
        ("Status", ", ".join(statuses) if statuses else None),
        ("Nameservers", nameservers),
        ("DNSSEC", (payload.get("secureDNS") or {}).get("delegationSigned")),
    ]


def ip_summary(payload: dict) -> list[tuple[str, object]]:
    roles = entities_by_role(payload)
    start, end = payload.get("startAddress"), payload.get("endAddress")
    # RFC 9083 cidr0 extension (ARIN, RIPE, APNIC…): the block as CIDR.
    cidrs = []
    for block in payload.get("cidr0_cidrs") or []:
        if isinstance(block, dict):
            prefix = block.get("v4prefix") or block.get("v6prefix")
            if prefix and block.get("length") is not None:
                cidrs.append(f"{prefix}/{block['length']}")
    return [
        ("Address range", f"{start} – {end}" if start and end else None),
        ("CIDR", ", ".join(cidrs) or None),
        ("Handle", payload.get("handle")),
        ("Name", payload.get("name")),
        ("Type", payload.get("type")),
        ("Country", payload.get("country")),
        ("Registered", registration_date(payload)),
        ("Last changed", _event(payload.get("events"), "last changed")),
        ("Registrant", roles.get("registrant") or roles.get("administrative")),
        ("Abuse contact", abuse_email(payload)),
        ("Parent handle", payload.get("parentHandle")),
    ]
