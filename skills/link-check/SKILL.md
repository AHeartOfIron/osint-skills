---
name: link-check
description: >
  Check what a link really opens before anyone clicks it: look-alike and
  homoglyph domains, "brand@evil" tricks, shorteners, open redirects, download
  links, and Telegram deep links (tg://msg_url, proxy, login, invite, gifts).
  Use when the user pastes a suspicious URL, a QR code's text, a link from an
  SMS, chat or email, or asks "is this link safe?".
---

# Link check

## Run

The script lives two folders up from this skill's base directory:

```bash
python3 "<base>/../../scripts/osint.py" link "<url>" ["<url2>" ...]
python3 "<base>/../../scripts/osint.py" link "<url>" --expand    # follow redirects
```

On Windows use `py` or `python` instead of `python3`. Quote every URL.

- Without `--expand` nothing is sent anywhere: the check is offline.
- `--expand` contacts every server in the redirect chain (HEAD requests, no page
  is downloaded). Ask the user before using it on a link that may be targeted at
  them personally: opening a tracking link can confirm to the sender that it was read.

## Read the result

JSON per URL: `host`, `registrable` (the part someone bought), `host_unicode`
for international names, `telegram` for Telegram links (`action`, `meaning`,
`prefilled_text`), `redirects` and `final` with `--expand`, and `findings`
with `level` high / medium / info.

## Tell the user

1. One line verdict first: **do not open**, **careful**, or **looks normal**.
   Any `high` finding means "do not open".
2. Say who really owns the link (`registrable`), in plain words.
3. For Telegram links, explain what tapping it does. `msg_url` / `share`
   only pre-fill a message: nothing is sent until the person presses Send.
   `proxy`, `socks` and `login` links are the dangerous ones.
4. If it was already opened: for a login page, change that password and
   sign out other sessions; for a downloaded file, do not run it; for a
   Telegram login link, check Settings > Devices and end unknown sessions.

## Limits

- "Looks normal" is not "safe". A real domain can still host bad content, and
  a new scam domain with a neutral name has nothing to flag. Say so.
- The registrable-domain logic uses a short suffix list, not the full Public
  Suffix List. Rare country suffixes may be split wrongly.
- Do not visit the page in a browser tool to "check" it unless the user asks.
