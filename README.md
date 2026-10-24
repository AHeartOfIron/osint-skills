# osint-skills

[![tests](https://github.com/AHeartOfIron/osint-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/AHeartOfIron/osint-skills/actions/workflows/ci.yml)

Defensive OSINT skills for [Claude Code](https://docs.claude.com/en/docs/claude-code).
Paste a suspicious link, email or photo and ask Claude about it. It runs a real check and explains the result in plain words.

- Pure Python standard library. No `pip install`, no API keys, no accounts.
- Every check prints JSON, so it also works without Claude.
- Offline wherever possible. Link, email and photo checks never contact anything.

| Skill | Ask Claude | What it checks |
|---|---|---|
| `link-check` | "Is this link safe?" | look-alike and homoglyph domains (`pаypal.com` with a Cyrillic `а`), `brand.com@evil.site`, shorteners, open redirects, download links, **Telegram deep links** (`tg://msg_url`, proxy, login, invites, gifts), redirect chains |
| `email-headers` | "Is this email real?" | SPF, DKIM, DMARC verdicts, spoofed display names, look-alike sender domains, Reply-To traps, free mailboxes posing as banks, the real origin server |
| `photo-metadata` | "What does this photo reveal?" | GPS location, camera, serial number, dates, editing software; makes a clean copy without metadata (JPEG, PNG) |
| `domain-check` | "Can someone fake mail from my domain?" | DNS, SPF and DMARC strength, registration date and registrar (RDAP), subdomains from certificate logs |
| `ip-lookup` | "Who owns this IP from my logs?" | private or public, owner network, country, abuse contact, reverse DNS, hosting or VPN, Tor exit |

## Install in Claude Code

```text
/plugin marketplace add AHeartOfIron/osint-skills
/plugin install osint-skills@osint-skills
```

Then just ask, for example:

> Someone sent me `tg://msg_url?url=t.me/nft/...&text=...` in Telegram. What happens if I tap it?

> Here are the headers of an email from "PayPal". Is it real?

> Remove the location from `holiday.jpg` before I post it.

Python 3.9 or newer must be installed (`python3`, or `py` on Windows).

## Use without Claude

```bash
python3 scripts/osint.py link "https://paypal.com@evil.example/login"
python3 scripts/osint.py email message.eml
python3 scripts/osint.py photo IMG_1234.jpg --strip IMG_1234_clean.jpg
python3 scripts/osint.py domain example.com --subdomains
python3 scripts/osint.py ip 203.0.113.7 --tor
```

Example:

```json
{
  "url": "tg://msg_url?url=t.me/nft/PoolFloat-1&text=1500%20stars",
  "telegram": { "action": "msg_url", "level": "medium",
                "meaning": "Opens a chat picker with a ready-made message. Nothing is sent until you press Send. ..." },
  "prefilled_text": "1500 stars",
  "findings": [
    { "level": "medium", "text": "Telegram: Opens a chat picker with a ready-made message. ..." },
    { "level": "medium", "text": "Inside the message: Telegram: A collectible gift page. Scams offer to sell or 'unlock' gifts ..." }
  ]
}
```

## What it contacts

| Check | Network |
|---|---|
| link | nothing; with `--expand`, each server in the redirect chain (HEAD only) |
| email, photo | nothing |
| domain | DNS-over-HTTPS (Cloudflare, Google), rdap.org; crt.sh with `--subdomains` |
| ip | rdap.org, reverse DNS; Tor Project exit list with `--tor` |

The target of a check (a site, an IP) is never scanned or probed.

## Ethics

These tools are for defence: checking what reaches you, protecting your own
accounts and domains, verifying material before publishing it, and reporting
abuse. The skills tell Claude not to help locate or profile private people.

## Tests

```bash
pip install pytest
pytest
```

36 offline tests: phishing links and real sites, a forged PayPal email, a JPEG
built byte by byte with GPS data, DNS and RDAP parsing.

## Author

Illia Usachov, [ARMSMA](https://armsma.org), Geneva. Parts of these checks also run in the
free tools of [Nocton](https://nocton.armsma.org). MIT license.
