"""IP check: address type, network owner and abuse contact (RDAP), reverse DNS, optional Tor exit list."""

from __future__ import annotations

import ipaddress
import socket

from . import net


def classify(ip: str) -> dict:
    a = ipaddress.ip_address(ip.strip().strip("[]"))
    kind = ("loopback" if a.is_loopback else "link-local" if a.is_link_local else "private" if a.is_private
            else "multicast" if a.is_multicast else "reserved" if a.is_reserved or a.is_unspecified else "public")
    return {"ip": str(a), "version": a.version, "kind": kind}


def rdap_summary(d: dict) -> dict:
    out = {"network": d.get("name"), "handle": d.get("handle"), "country": d.get("country"),
           "range": f"{d.get('startAddress')} - {d.get('endAddress')}" if d.get("startAddress") else None,
           "cidr": [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in d.get("cidr0_cidrs", [])],
           "owner": None, "abuse_email": None}
    for roles, e in net.rdap_entities(d):
        if out["owner"] is None and ("registrant" in roles or "administrative" in roles):
            out["owner"] = net.vcard_field(e, "fn", "org")
        if out["abuse_email"] is None and "abuse" in roles:
            out["abuse_email"] = net.vcard_field(e, "email")
    for r in d.get("remarks", []):
        text = " ".join(r.get("description", []))
        if text and len(text) < 300:
            out.setdefault("remarks", []).append(text)
    return out


def reverse_dns(ip: str) -> str | None:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(old)


def run(ip: str, tor: bool = False) -> dict:
    out = classify(ip)
    out["errors"] = []
    if out["kind"] != "public":
        out["findings"] = [{"level": "info", "text": f"A {out['kind']} address. It is not on the internet, so it has no public owner."}]
        return out
    try:
        out["registry"] = rdap_summary(net.get_json(f"https://rdap.org/ip/{out['ip']}"))
    except Exception as e:
        out["errors"].append(f"RDAP: {e}")
    out["reverse_dns"] = reverse_dns(out["ip"])
    if tor:
        try:
            out["tor_exit"] = out["ip"] in set(net.get_text("https://check.torproject.org/torbulkexitlist").split())
        except Exception as e:
            out["errors"].append(f"Tor list: {e}")
    f = out["findings"] = []
    reg = out.get("registry") or {}
    hosting = ("hosting", "cloud", "server", "datacenter", "data center", "vps", "amazon", "google", "microsoft",
               "digitalocean", "ovh", "hetzner", "linode", "akamai", "cloudflare", "contabo", "m247", "leaseweb")
    text = " ".join(str(x) for x in (reg.get("network"), reg.get("owner"), out.get("reverse_dns")) if x).lower()
    if any(h in text for h in hosting):
        f.append({"level": "info", "text": "Looks like a hosting or cloud network: a server, VPN or proxy rather than a home connection."})
    if out.get("tor_exit"):
        f.append({"level": "medium", "text": "A Tor exit node. The real sender is hidden behind it."})
    f.append({"level": "info", "text": "An IP gives a network and roughly a country or city, never a person or a street address."})
    if reg.get("abuse_email"):
        f.append({"level": "info", "text": f"To report abuse from this address, write to {reg['abuse_email']}."})
    return out
