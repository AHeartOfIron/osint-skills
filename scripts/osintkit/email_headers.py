"""Email header check: who really sent a message, what the receiving server verified, where it came from."""

from __future__ import annotations

import ipaddress
import re
from email import policy
from email.parser import BytesHeaderParser
from email.utils import getaddresses, parseaddr

from .links import lookalike, registrable

FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com",
             "me.com", "aol.com", "gmx.com", "gmx.ch", "gmx.de", "gmx.net", "web.de", "mail.ru", "yandex.ru",
             "ukr.net", "proton.me", "protonmail.com", "tutanota.com", "bluewin.ch", "zoho.com"}
OFFICIAL_WORDS = ("bank", "support", "security", "police", "admin", "service", "official", "team", "billing",
                  "account", "helpdesk", "it department", "post", "customs", "tax", "government", "court")
IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")


def _addr(value: str | None) -> dict | None:
    if not value:
        return None
    name, addr = parseaddr(value)
    dom = addr.rsplit("@", 1)[-1].lower() if "@" in addr else None
    return {"name": name, "address": addr, "domain": dom}


def _public_ip(s: str) -> str | None:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def parse_received(lines: list[str]) -> list[dict]:
    """Received headers, oldest hop first (they are stacked newest on top)."""
    hops = []
    for line in reversed(lines):
        one = " ".join(line.split())
        body, _, date = one.rpartition(";")
        m_from = re.search(r"\bfrom\s+(\S+)", body)
        m_by = re.search(r"\bby\s+(\S+)", body)
        ips = [ip for ip in (_public_ip(x) for x in IP_RE.findall(body)) if ip]
        hops.append({"from": m_from.group(1) if m_from else None, "by": m_by.group(1) if m_by else None,
                     "public_ips": ips, "date": date.strip() or None})
    return hops


def auth_results(values: list[str]) -> dict:
    """spf / dkim / dmarc verdicts. The topmost header is the one your own provider added."""
    out: dict = {}
    for v in values:
        for method, result in re.findall(r"\b(spf|dkim|dmarc|arc)=(\w+)", v, re.I):
            out.setdefault(method.lower(), result.lower())
    return out


def analyse(raw: bytes) -> dict:
    msg = BytesHeaderParser(policy=policy.compat32).parsebytes(raw)
    get = lambda k: str(msg.get(k)) if msg.get(k) is not None else None
    frm, reply, ret, sender = _addr(get("From")), _addr(get("Reply-To")), _addr(get("Return-Path")), _addr(get("Sender"))
    auth = auth_results([str(v) for v in msg.get_all("Authentication-Results", [])])
    if "spf" not in auth:
        for v in msg.get_all("Received-SPF", []):
            auth["spf"] = str(v).split()[0].lower()
            break
    hops = parse_received([str(v) for v in msg.get_all("Received", [])])
    origin = next((h["public_ips"][0] for h in hops if h["public_ips"]), None)
    mid = get("Message-ID")
    mid_dom = mid.strip("<> ").rsplit("@", 1)[-1].lower() if mid and "@" in mid else None

    out = {"subject": get("Subject"), "date": get("Date"), "from": frm, "reply_to": reply, "return_path": ret,
           "sender": sender, "to": [a for _, a in getaddresses(msg.get_all("To", []))],
           "message_id_domain": mid_dom, "authentication": auth, "hops": hops, "origin_ip": origin,
           "mailer": get("X-Mailer") or get("User-Agent"), "findings": []}
    add = lambda level, text: out["findings"].append({"level": level, "text": text})

    if not frm or not frm["domain"]:
        add("high", "No readable From address.")
        return out
    fdom = frm["domain"]

    if auth.get("dmarc") == "fail":
        add("high", f"DMARC failed: the message is NOT verified as coming from {fdom}.")
    if auth.get("spf") in ("fail", "softfail"):
        add("medium" if auth.get("dmarc") == "pass" else "high", f"SPF {auth['spf']}: the sending server is not authorised for its domain.")
    if auth.get("dkim") in ("fail", "none", "neutral", "permerror", "temperror"):
        add("medium", f"DKIM {auth['dkim']}: no valid signature from the sender.")
    if not auth:
        add("info", "No Authentication-Results header. Either these are not the full headers, or the receiver recorded no checks.")
    if auth.get("dmarc") == "pass" and auth.get("spf") in (None, "pass") and auth.get("dkim") in (None, "pass"):
        add("info", f"Checks passed. The message really comes from {fdom}. That proves the domain, not that the domain is honest.")

    name = frm["name"] or ""
    m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", name)
    if m and registrable(m.group(1).lower()) != registrable(fdom):
        add("high", f"The display name shows '{m.group(0)}' but the real address is {frm['address']}.")
    brand = lookalike(fdom)
    if brand:
        add("high", f"The sender domain {fdom} imitates '{brand}'.")
    if fdom in FREE_MAIL and any(w in name.lower() for w in OFFICIAL_WORDS):
        add("medium", f"Named like an organisation ('{name}') but sent from a free {fdom} mailbox.")
    if reply and reply["domain"] and registrable(reply["domain"]) != registrable(fdom):
        add("medium", f"Replies go to {reply['address']}, a different domain from the sender. Common in fraud.")
    if ret and ret["domain"] and registrable(ret["domain"]) != registrable(fdom):
        add("info", f"Bounces go to {ret['domain']}. Normal for newsletters and mail services, odd for a person.")
    if mid_dom and registrable(mid_dom) != registrable(fdom) and auth.get("dmarc") != "pass":
        add("info", f"Message-ID was made by {mid_dom}, not by {fdom}.")
    return out
