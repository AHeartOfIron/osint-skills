---
name: domain-check
description: >
  Check a domain: DNS records, mail security (SPF, DMARC), registration date,
  registrar and status (RDAP), and optionally subdomains from public
  certificate logs. Use when the user asks whether a website or sender domain
  is trustworthy, how new it is, who registered it, whether their own domain
  can be spoofed by email, or what subdomains exist.
---

# Domain check

## Run

```bash
python3 "<base>/../../scripts/osint.py" domain example.com
python3 "<base>/../../scripts/osint.py" domain example.com --subdomains
```

`<base>` is this skill's base directory. On Windows use `py` or `python`.
A full URL or an email address also works; the domain is taken from it.

Network use: DNS-over-HTTPS (Cloudflare, Google), rdap.org, and crt.sh only
with `--subdomains` (slow, sometimes down). The target site itself is never contacted.

## Read the result

`dns` (A, AAAA, MX, NS, TXT, CAA, DMARC), `registration` (registered,
expires, registrar, status, nameservers), `subdomains`, `findings`, and
`errors` for lookups that failed.

## Tell the user

1. **New domain** (high finding, under 30 days) is the strongest scam signal.
   Combine it with what the site claims to be: a "bank" registered last week is fake.
2. **Mail spoofing**: no SPF, no DMARC or `p=none` means anyone can send mail
   that looks like it comes from this domain. If it is the user's own domain,
   give the fix: publish SPF ending in `-all` (or `~all`) and DMARC starting at
   `p=quarantine`, with their mail provider's values.
3. A failed lookup (listed in `errors`) is not a missing record. Say it could not be checked.
4. Many country registries (for example `.ch`, `.de`) return little or no RDAP
   data. A missing registration date is then normal, not suspicious.

## Ethics

Registration data of private people is redacted under GDPR. Do not try to
uncover who is behind a private person's domain; for abuse, use the
registrar's abuse contact instead.
