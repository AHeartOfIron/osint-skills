"""Domain check: DNS, mail security (SPF, DMARC), registration (RDAP), optional subdomains (crt.sh)."""

from __future__ import annotations

import datetime as dt

from . import net


def normalise(domain: str) -> str:
    d = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0].split("@")[-1].split(":")[0].strip(".")
    if d.startswith("www."):
        d = d[4:]
    return d.encode("idna").decode("ascii")


def rdap_summary(d: dict) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    registrar = next((net.vcard_field(e, "fn", "org") for roles, e in net.rdap_entities(d) if "registrar" in roles), None)
    return {"registered": events.get("registration"), "expires": events.get("expiration"),
            "updated": events.get("last changed"), "registrar": registrar, "status": d.get("status", []),
            "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])]}


def _days_since(iso: str | None, today: dt.date) -> int | None:
    if not iso:
        return None
    try:
        return (today - dt.date.fromisoformat(iso[:10])).days
    except ValueError:
        return None


def assess(records: dict, reg: dict | None, today: dt.date | None = None) -> list[dict]:
    """Turn raw records into findings a person can act on. No network here."""
    today = today or dt.date.today()
    f: list[dict] = []
    add = lambda level, text: f.append({"level": level, "text": text})

    # Only judge what was actually looked up: a failed lookup is not a missing record.
    if {"A", "AAAA", "MX"} <= records.keys() and not records["A"] and not records["AAAA"] and not records["MX"]:
        add("medium", "The domain has no web or mail address records. It may be parked, new or unused.")

    spf = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    if "TXT" not in records:
        pass
    elif not spf:
        add("medium", "No SPF record. Mail servers cannot check who may send mail for this domain.")
    elif len(spf) > 1:
        add("medium", "More than one SPF record. That is invalid, so receivers may ignore both.")
    else:
        tail = spf[0].split()[-1].lower()
        if tail == "+all":
            add("high", "SPF ends in +all: every server in the world is allowed to send as this domain.")
        elif tail == "?all":
            add("medium", "SPF ends in ?all (neutral): it does not block forged senders.")
        elif tail == "~all":
            add("info", "SPF ends in ~all (soft fail): forged mail is marked, not rejected.")

    dmarc = [t for t in records.get("DMARC", []) if t.lower().startswith("v=dmarc1")]
    if "DMARC" not in records:
        pass
    elif not dmarc:
        add("medium", "No DMARC record. Mail that fakes this domain is not blocked by policy.")
    else:
        tags = dict(p.strip().split("=", 1) for p in dmarc[0].split(";") if "=" in p)
        policy = tags.get("p", "").strip().lower()
        if policy == "none":
            add("info", "DMARC policy is p=none: monitoring only, forged mail still gets delivered.")
        elif policy in ("quarantine", "reject"):
            add("info", f"DMARC policy is p={policy}: forged mail is filtered.")

    if reg:
        age = _days_since(reg.get("registered"), today)
        if age is not None and age < 30:
            add("high", f"Registered {age} days ago. Very new domains are common in phishing and scams.")
        elif age is not None and age < 180:
            add("medium", f"Registered {age} days ago, less than six months.")
        left = _days_since(reg.get("expires"), today)
        if left is not None and -30 < left <= 0:
            add("info", f"Registration expires in {-left} days.")
        holds = [s for s in reg.get("status", []) if "hold" in s.lower()]
        if holds:
            add("high", f"Registry status {', '.join(holds)}: the domain is suspended, often after abuse reports.")
    return f


def crtsh_subdomains(domain: str, limit: int = 300) -> list[str]:
    """Names seen in public certificate logs. Slow and sometimes down."""
    rows = net.get_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=45)
    names = set()
    for r in rows:
        for n in str(r.get("name_value", "")).splitlines():
            n = n.strip().lower().removeprefix("*.")
            if n.endswith(domain) and n != domain:
                names.add(n)
    return sorted(names)[:limit]


def run(domain: str, subdomains: bool = False) -> dict:
    d = normalise(domain)
    out: dict = {"domain": d, "errors": []}
    records: dict = {}
    for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            records[t] = net.dns(d, t)
        except Exception as e:  # one failed lookup should not hide the rest
            out["errors"].append(f"DNS {t}: {e}")
    try:
        records["DMARC"] = net.dns(f"_dmarc.{d}", "TXT")
    except Exception as e:
        out["errors"].append(f"DNS DMARC: {e}")
    out["dns"] = records

    reg = None
    try:
        reg = rdap_summary(net.get_json(f"https://rdap.org/domain/{d}"))
    except Exception as e:
        out["errors"].append(f"RDAP: {e} (some country domains, e.g. .ch, publish little or nothing)")
    out["registration"] = reg

    if subdomains:
        try:
            out["subdomains"] = crtsh_subdomains(d)
        except Exception as e:
            out["errors"].append(f"crt.sh: {e}")
    out["findings"] = assess(records, reg)
    return out
