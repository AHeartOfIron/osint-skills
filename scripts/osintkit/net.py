"""Small HTTP and DNS helpers shared by the checks. Standard library only."""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

UA = "osint-skills/0.1 (+https://github.com/AHeartOfIron/osint-skills)"
DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


def get_json(url: str, timeout: float = 15, headers: dict | None = None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def get_text(url: str, timeout: float = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def txt_value(data: str) -> str:
    """DNS JSON gives TXT records as quoted chunks: '"v=spf1 a" " -all"'. Join them."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(parts) if parts else data


# Tried in order. The bare IP works even where the resolver name itself is blocked.
DOH = ("https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query", "https://dns.google/resolve")


def dns(name: str, rtype: str) -> list[str]:
    """Look up one record type over DNS-over-HTTPS, so the answer does not depend on the local resolver."""
    query = urllib.parse.urlencode({"name": name, "type": rtype})
    last: Exception | None = None
    for endpoint in DOH:
        try:
            d = get_json(f"{endpoint}?{query}", timeout=10, headers={"Accept": "application/dns-json"})
            break
        except Exception as e:
            last = e
    else:
        raise last or OSError("no DNS-over-HTTPS endpoint answered")
    if d.get("Status") not in (0, 3):  # 0 found, 3 no such name; anything else is a failed lookup
        raise OSError(f"DNS status {d.get('Status')}")
    out = [a["data"] for a in d.get("Answer", []) if a.get("type") == DNS_TYPES[rtype]]
    return [txt_value(v) for v in out] if rtype == "TXT" else out


def vcard_field(entity: dict, *names: str) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] in names and isinstance(item[3], str) and item[3].strip():
            return item[3].strip()
    return None


def rdap_entities(d: dict):
    """Every entity in an RDAP answer, nested ones included, as (roles, entity)."""
    stack = list(d.get("entities", []))
    while stack:
        e = stack.pop(0)
        yield e.get("roles", []), e
        stack.extend(e.get("entities", []))
