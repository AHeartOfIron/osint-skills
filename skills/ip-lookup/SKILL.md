---
name: ip-lookup
description: >
  Look up an IP address: private or public, which network and organisation own
  it, the country of registration, the abuse contact, reverse DNS, whether it
  looks like hosting or a VPN, and optionally whether it is a Tor exit. Use
  when the user finds an IP in logs, email headers or a login alert and asks
  who it belongs to or where to report abuse.
---

# IP lookup

## Run

```bash
python3 "<base>/../../scripts/osint.py" ip 203.0.113.7
python3 "<base>/../../scripts/osint.py" ip 2001:db8::1 --tor
```

`<base>` is this skill's base directory. On Windows use `py` or `python`.
Network use: rdap.org, a reverse DNS query, and the Tor Project exit list with
`--tor`. The address itself is never contacted (no ping, no scan).

## Read the result

`kind` (public, private, loopback, link-local...), `registry` (network,
owner, country, range, cidr, abuse_email), `reverse_dns`, `tor_exit`, `findings`.

## Tell the user

1. Private and local addresses (192.168.x, 10.x, 127.0.0.1) are inside a
   network. They identify nothing on the internet.
2. Name the owner network and its country. Say clearly: an IP shows an
   internet provider or hosting company and roughly a region, never a person
   or a street address.
3. Hosting, VPN and Tor addresses hide the real user behind them.
4. For abuse (attacks, spam, phishing hosting), give `abuse_email` and suggest
   sending the evidence there: time with time zone, logs, headers.
5. For an unknown login alert from this IP: change the password, end other
   sessions, turn on two-step login.

## Ethics

Do not help pin an IP to a private individual. Identifying a subscriber needs
the provider and a legal process.
