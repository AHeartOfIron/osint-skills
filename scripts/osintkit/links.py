"""Link check: what a URL really points to, look-alike domains, Telegram deep links, redirect chains."""

from __future__ import annotations

import ipaddress
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

from . import net

# Suffixes under which anyone can register a name. A short list, not the full
# Public Suffix List: good enough to find the part of a host that was bought.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "co.il", "co.za", "com.tr",
    "com.ua", "org.ua", "gov.ua", "in.ua", "kiev.ua", "com.pl", "co.in", "com.cn", "com.mx", "co.nz",
    "github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
    "herokuapp.com", "blogspot.com", "glitch.me", "azurewebsites.net", "appspot.com", "ngrok.io", "ngrok-free.app",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "s.id", "lnkd.in", "t.ly", "clck.ru", "v.gd"}
ABUSED_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "cam", "icu",
               "rest", "quest", "sbs", "cfd", "lol", "monster", "buzz"}
RISKY_EXT = (".apk", ".exe", ".scr", ".msi", ".bat", ".cmd", ".js", ".vbs", ".jar", ".iso", ".img", ".lnk",
             ".hta", ".ps1", ".dmg", ".pkg", ".appx", ".xll", ".docm", ".xlsm")
BRANDS = ["paypal", "apple", "icloud", "google", "microsoft", "office365", "outlook", "amazon", "facebook",
          "instagram", "whatsapp", "telegram", "netflix", "binance", "coinbase", "metamask", "linkedin",
          "ubs", "postfinance", "raiffeisen", "revolut", "swisspost", "dhl", "fedex", "privatbank", "monobank"]
# Real brand domains whose names contain the brand plus more letters.
LEGIT = {"googleusercontent.com", "googleapis.com", "googlemail.com", "googlevideo.com", "microsoftonline.com",
         "microsoft365.com", "office365.com", "amazonaws.com", "amazonpay.com", "facebookmail.com", "whatsapp.net",
         "paypalobjects.com", "icloud-content.com", "applecontent.com", "linkedin.com", "telegram.org", "outlook.com"}
REDIRECT_PARAMS = {"url", "u", "redirect", "redirect_uri", "redirect_url", "next", "target", "dest", "destination",
                   "goto", "continue", "return", "returnurl", "out", "link"}
CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d",
    "ѕ": "s", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k",
    "τ": "t", "ρ": "p", "0": "o", "1": "l", "3": "e", "5": "s", "!": "i", "|": "l",
})

# Telegram deep links: what opening one does. tg://<action> and t.me/<action>.
TELEGRAM = {
    "msg_url": ("medium", "Opens a chat picker with a ready-made message. Nothing is sent until you press Send. "
                          "Read the text first: scams use this to make you forward spam, and spam reports get accounts limited."),
    "msg": ("medium", "Opens a chat picker with a ready-made message. Nothing is sent until you press Send."),
    "share": ("medium", "Opens a chat picker with a ready-made message. Nothing is sent until you press Send."),
    "resolve": ("info", "Opens a user, channel or bot by its username."),
    "join": ("medium", "Asks you to join a group or channel by invite. Check who runs it before joining."),
    "proxy": ("high", "Asks Telegram to route your traffic through a third-party proxy. Its owner sees your IP address and when you are online."),
    "socks": ("high", "Asks Telegram to route your traffic through a third-party proxy. Its owner sees your IP address and when you are online."),
    "login": ("high", "A login token. Opening a login link or QR code somebody sent you can sign THEIR device into YOUR account."),
    "passport": ("high", "Asks to share documents from Telegram Passport."),
    "addlist": ("medium", "Adds a whole folder of chats at once."),
    "invoice": ("medium", "A payment request. Check who is asking before paying."),
    "giftcode": ("medium", "A gift or Premium code. Fake gift offers are a common scam."),
    "nft": ("medium", "A collectible gift page. Scams offer to sell or 'unlock' gifts for Stars or crypto."),
    "confirmphone": ("medium", "Asks to confirm a phone number. Never pass the code you receive to anyone."),
    "addstickers": ("info", "Adds a sticker pack."), "addemoji": ("info", "Adds an emoji pack."),
    "addtheme": ("info", "Adds a colour theme."), "setlanguage": ("info", "Changes the app language."),
    "privatepost": ("info", "Opens a message in a private channel."), "bg": ("info", "Sets a chat background."),
}


def registrable(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def skeleton(s: str) -> str:
    """Fold look-alike characters to plain Latin: 'раураl' and 'paypa1' both become 'paypal'."""
    s = unicodedata.normalize("NFKC", s.lower()).translate(CONFUSABLE)
    return s.replace("rn", "m").replace("vv", "w")


def _distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(domain: str) -> str | None:
    """The brand a registrable domain imitates, if any. The real brand domain returns None."""
    name = registrable(domain).split(".")[0]
    try:
        name = name.encode("ascii").decode("idna") if name.startswith("xn--") else name
    except UnicodeError:
        pass
    if name in BRANDS or registrable(domain) in LEGIT:
        return None
    sk = skeleton(name)
    for brand in BRANDS:
        if sk == brand or (len(brand) >= 5 and brand in sk.replace("-", "")) or (len(brand) >= 6 and _distance(sk, brand) == 1):
            return brand
    return None


def _scripts(s: str) -> set[str]:
    out = set()
    for ch in s:
        if ch.isalpha():
            out.add(unicodedata.name(ch, "UNKNOWN").split()[0])
    return out


def telegram(url: str) -> dict | None:
    p = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qs(p.query)
    if p.scheme == "tg":
        action = (p.netloc or p.path).strip("/").lower()
    elif p.hostname in ("t.me", "telegram.me", "telegram.dog"):
        path = p.path.strip("/")
        head = path.split("/")[0].lower()
        if head.startswith("+") or head == "joinchat":
            action = "join"
        elif head in TELEGRAM:
            action = head
        elif head == "share":
            action = "share"
        else:
            action = "resolve"
    else:
        return None
    level, meaning = TELEGRAM.get(action, ("medium", "An unusual Telegram action. Do not open it unless you know the sender."))
    info = {"action": action, "level": level, "meaning": meaning}
    for key in ("url", "text", "domain", "start", "server", "port"):
        if key in q:
            info[key] = q[key][0]
    return info


def analyse(url: str) -> dict:
    url = url.strip()
    if "://" not in url and not url.lower().startswith(("javascript:", "data:", "vbscript:", "tg:")):
        url = "https://" + url
    p = urllib.parse.urlsplit(url)
    out: dict = {"url": url, "scheme": p.scheme.lower(), "findings": []}
    add = lambda level, text: out["findings"].append({"level": level, "text": text})

    if out["scheme"] in ("javascript", "data", "vbscript"):
        add("high", f"A {out['scheme']}: link runs code or loads content directly instead of opening a site.")
        return out

    tg = telegram(url)
    if tg:
        out["telegram"] = tg
        add(tg["level"], "Telegram: " + tg["meaning"])
        if tg.get("text"):
            out["prefilled_text"] = tg["text"]
        if tg.get("url"):
            inner = analyse(tg["url"])
            out["inner"] = inner
            out["findings"] += [{"level": f["level"], "text": "Inside the message: " + f["text"]} for f in inner["findings"]]
        if out["scheme"] == "tg":
            return out

    host = p.hostname or ""
    out["host"] = host
    if p.username is not None or "@" in p.netloc:
        add("high", f"Everything before '@' in the address is ignored. The real site is {host}.")
    if out["scheme"] == "http":
        add("info", "Not encrypted (http). Anyone on the network can read or change the page.")

    try:
        ipaddress.ip_address(host)
        add("medium", "The link points to a bare IP address instead of a name. Legitimate services rarely do this.")
        return out
    except ValueError:
        pass

    try:
        shown = host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        shown = host
    if shown != host or not host.isascii():
        out["host_unicode"] = shown
        scripts = _scripts(shown.replace(".", ""))
        level = "high" if len(scripts) > 1 else "medium"
        add(level, f"International domain shown as '{shown}' (scripts: {', '.join(sorted(scripts))}). Letters from another alphabet can imitate a real name.")

    reg = registrable(host)
    out["registrable"] = reg
    brand = lookalike(reg)
    if brand:
        add("high", f"'{registrable(shown)}' imitates the brand '{brand}'. It is not the real {brand} site.")
    else:
        labels = skeleton(host[: -len(reg)].strip(".")).split(".")
        for b in BRANDS:
            if len(b) >= 4 and any(b in lab for lab in labels) and reg not in LEGIT:
                add("high", f"'{b}' appears only in the subdomain. The site really belongs to {reg}.")
                break
    if reg in SHORTENERS or host in SHORTENERS:
        add("medium", "A link shortener hides the real destination. Expand it before opening (--expand).")
    tld = reg.rsplit(".", 1)[-1]
    if tld in ABUSED_TLDS:
        add("medium", f"The .{tld} ending is cheap and often used for throwaway scam sites.")
    if host.count(".") - reg.count(".") >= 3:
        add("info", "Many subdomain levels. Long hosts are used to push the real domain out of view on phones.")
    if p.path.lower().endswith(RISKY_EXT):
        add("high", f"The link downloads a program or macro file ({p.path.rsplit('.', 1)[-1]}). Do not run it.")
    for k, vals in urllib.parse.parse_qs(p.query).items():
        if k.lower() in REDIRECT_PARAMS and vals and vals[0].lower().startswith(("http://", "https://", "//")):
            add("medium", f"Carries another address in '{k}': this site may forward you to {vals[0]}.")
            break
    if len(url) > 200:
        add("info", f"Very long link ({len(url)} characters).")
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None  # report each hop ourselves instead of following it


def expand(url: str, max_hops: int = 10) -> list[dict]:
    """Follow redirects one by one without downloading pages. This DOES contact every server on the way."""
    opener = urllib.request.build_opener(_NoRedirect)
    chain = []
    for _ in range(max_hops):
        hop: dict = {"url": url}
        status, location = None, None
        for method in ("HEAD", "GET"):
            req = urllib.request.Request(url, method=method, headers={"User-Agent": net.UA})
            try:
                with opener.open(req, timeout=10) as r:
                    status = r.status
            except urllib.error.HTTPError as e:
                status, location = e.code, e.headers.get("Location")
            except Exception as e:
                hop["error"] = str(e)
                break
            if status != 405:
                break
        hop["status"] = status
        chain.append(hop)
        if not location or status not in (301, 302, 303, 307, 308):
            break
        url = urllib.parse.urljoin(url, location)
    return chain


def run(urls: list[str], do_expand: bool = False) -> list[dict]:
    results = []
    for u in urls:
        r = analyse(u)
        if do_expand and r["scheme"] in ("http", "https"):
            try:
                r["redirects"] = expand(r["url"])
                final = r["redirects"][-1]["url"]
                if final != r["url"]:
                    r["final"] = analyse(final)
            except Exception as e:
                r["redirects_error"] = str(e)
        results.append(r)
    return results
