---
name: email-headers
description: >
  Forensics on raw email headers: SPF, DKIM and DMARC verdicts, spoofed display
  names, look-alike sender domains, Reply-To traps, free mailboxes posing as
  organisations, and the server and IP the message really came from. Use when
  the user pastes headers or an .eml file and asks "is this email real?",
  "who sent this?" or "is this phishing?".
---

# Email headers

## Get the headers

The body is not needed. Ask the user for the full headers:

- Gmail: open the message > three dots > **Show original**.
- Outlook: open the message > three dots > **View** > **View message source**.
- Apple Mail: **View** > **Message** > **All Headers**.
- Thunderbird: **More** > **View Source**, or save as `.eml`.

Save what they paste to a file (or pipe it on stdin).

## Run

```bash
python3 "<base>/../../scripts/osint.py" email message.eml
python3 "<base>/../../scripts/osint.py" email - < headers.txt
```

`<base>` is this skill's base directory. On Windows use `py` or `python`.
Fully offline: no lookups are made.

## Read the result

`from`, `reply_to`, `return_path`, `authentication` (spf / dkim / dmarc as the
receiving server recorded them), `hops` (oldest first), `origin_ip` (first
public IP in the chain), `findings`.

## Tell the user

1. Verdict first. `DMARC failed`, a spoofed display name or a look-alike
   domain means: treat it as fake, do not click, do not reply.
2. Explain who really sent it: the real address and domain, in plain words.
3. "Checks passed" proves only that the mail came from that domain. A scammer
   can own a domain and pass every check. Say this when it matters.
4. For a deeper look, offer the domain-check skill on the sender domain and
   ip-lookup on `origin_ip` (to find the provider's abuse contact).
5. Next steps for real phishing: report it in the mail app, and if a password
   was typed in, change it and turn on two-step login.

## Limits

- Headers above the receiving server can be forged; only the hops added by the
  user's own provider (the top ones) are trustworthy.
- Big providers (Gmail, Outlook) often hide the sender's own IP. Then
  `origin_ip` is the provider's server, not the person.
