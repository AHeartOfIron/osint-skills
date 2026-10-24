"""Offline tests: everything that does not need the network."""
import datetime as dt
import struct

import pytest

from osintkit import domain, email_headers, ip, links, photo


# ---------- links

@pytest.mark.parametrize("url,level,needle", [
    ("https://paypal.com@evil.example/login", "high", "before '@'"),
    ("https://xn--pypal-4ve.com", "high", "imitates the brand 'paypal'"),
    ("https://paypa1-secure.top/x", "high", "imitates the brand 'paypal'"),
    ("https://login.microsoft.com.verify-account.info/", "high", "only in the subdomain"),
    ("https://bit.ly/3abc", "medium", "shortener"),
    ("http://203.0.113.9/a", "medium", "bare IP"),
    ("https://example.com/update.apk", "high", "downloads a program"),
    ("https://example.com/r?url=https://evil.example", "medium", "forward you"),
    ("javascript:alert(1)", "high", "runs code"),
    ("tg://proxy?server=1.2.3.4&port=443&secret=x", "high", "proxy"),
    ("https://t.me/login/abc", "high", "login"),
    ("https://t.me/+AbCdEf", "medium", "join"),
])
def test_link_flags(url, level, needle):
    r = links.analyse(url)
    assert any(f["level"] == level and needle in f["text"] for f in r["findings"]), r["findings"]


@pytest.mark.parametrize("url", ["https://www.paypal.com/signin", "https://accounts.google.com",
                                 "https://googleusercontent.com/a", "https://www.bbc.co.uk/news",
                                 "https://github.com/AHeartOfIron"])
def test_real_sites_are_quiet(url):
    assert [f for f in links.analyse(url)["findings"] if f["level"] == "high"] == []


def test_msg_url_reads_the_prefilled_message():
    r = links.analyse("tg://msg_url?url=t.me/nft/PoolFloat-1&text=1500%20stars")
    assert r["telegram"]["action"] == "msg_url"
    assert r["prefilled_text"] == "1500 stars"
    assert any("Inside the message" in f["text"] and "gift" in f["text"] for f in r["findings"])


def test_registrable():
    assert links.registrable("a.b.example.co.uk") == "example.co.uk"
    assert links.registrable("evil.github.io") == "evil.github.io"
    assert links.registrable("www.example.com") == "example.com"


# ---------- email headers

PHISH = b"""Received: from mx.victim.ch (mx.victim.ch [10.0.0.5]) by inbox.victim.ch; Fri, 24 Oct 2026 10:00:03 +0200
Received: from mail.cheap-host.example (unknown [185.220.101.4]) by mx.victim.ch; Fri, 24 Oct 2026 10:00:01 +0200
Authentication-Results: mx.victim.ch; spf=softfail smtp.mailfrom=paypal.com; dkim=none; dmarc=fail header.from=paypal.com
From: "PayPal Security <service@paypal.com>" <alerts@paypa1-support.com>
Reply-To: refunds@gmail.com
Return-Path: <bounce@cheap-host.example>
Message-ID: <123@cheap-host.example>
Subject: Your account is limited
Date: Fri, 24 Oct 2026 10:00:00 +0200
To: you@victim.ch

"""


def test_phishing_headers():
    r = email_headers.analyse(PHISH)
    text = " | ".join(f["level"] + ":" + f["text"] for f in r["findings"])
    assert "high:DMARC failed" in text
    assert "display name shows 'service@paypal.com'" in text
    assert "imitates 'paypal'" in text
    assert "Replies go to refunds@gmail.com" in text
    assert r["origin_ip"] == "185.220.101.4"
    assert r["hops"][0]["from"] == "mail.cheap-host.example"  # oldest hop first


def test_clean_headers_pass():
    raw = (b"Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass header.from=armsma.org\n"
           b"From: ARMSMA <info@armsma.org>\nSubject: hi\n\n")
    r = email_headers.analyse(raw)
    assert [f for f in r["findings"] if f["level"] != "info"] == []
    assert any("Checks passed" in f["text"] for f in r["findings"])


# ---------- photo

def _rational_dms(v: float) -> bytes:
    d = int(v)
    m = int((v - d) * 60)
    s = round(((v - d) * 60 - m) * 60 * 100)
    return struct.pack("<IIIIII", d, 1, m, 1, s, 100)


def _tiff_with_gps() -> bytes:
    """Little-endian TIFF: IFD0 (Make, GPS pointer) and a GPS IFD for 46.2044 N, 6.1432 E."""
    make = b"TestCam\0"
    ifd0_at, gps_at = 8, 8 + 2 + 2 * 12 + 4
    data_at = gps_at + 2 + 4 * 12 + 4
    make_at, lat_at = data_at, data_at + len(make)
    lon_at = lat_at + 24
    t = b"II" + struct.pack("<HI", 42, ifd0_at)
    t += struct.pack("<H", 2) + struct.pack("<HHII", 0x010F, 2, len(make), make_at)
    t += struct.pack("<HHII", 0x8825, 4, 1, gps_at) + b"\0\0\0\0"
    t += struct.pack("<H", 4)
    t += struct.pack("<HHI", 1, 2, 2) + b"N\0\0\0"
    t += struct.pack("<HHII", 2, 5, 3, lat_at)
    t += struct.pack("<HHI", 3, 2, 2) + b"E\0\0\0"
    t += struct.pack("<HHII", 4, 5, 3, lon_at) + b"\0\0\0\0"
    return t + make + _rational_dms(46.2044) + _rational_dms(6.1432)


def _jpeg(tiff: bytes) -> bytes:
    app1 = b"Exif\0\0" + tiff
    com = b"secret note"
    return (b"\xff\xd8" + b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"
            + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
            + b"\xff\xfe" + struct.pack(">H", len(com) + 2) + com
            + b"\xff\xda" + struct.pack(">H", 8) + b"\x01\x01\x00\x00\x3f\x00" + b"PIXELS" + b"\xff\xd9")


def test_photo_reads_gps_and_camera():
    r = photo.read(_jpeg(_tiff_with_gps()))
    assert r["exif"]["make"] == "TestCam"
    assert r["gps"]["lat"] == pytest.approx(46.2044, abs=1e-4)
    assert r["gps"]["lon"] == pytest.approx(6.1432, abs=1e-4)
    assert r["other"]["comment"] == "secret note"
    assert r["findings"][0]["level"] == "high"


def test_photo_strip_keeps_pixels_drops_metadata():
    out = photo.strip(_jpeg(_tiff_with_gps()))
    r = photo.read(out)
    assert r["exif"] == {} and "gps" not in r and "comment" not in r["other"]
    assert out.endswith(b"PIXELS\xff\xd9") and b"JFIF" in out


def test_photo_without_metadata():
    r = photo.read(b"\xff\xd8\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00..\xff\xd9")
    assert "proves nothing" in r["findings"][0]["text"]


def test_photo_rejects_other_files():
    with pytest.raises(ValueError):
        photo.read(b"GIF89a....")


# ---------- domain

def test_domain_assess():
    today = dt.date(2026, 10, 25)
    rec = {"A": ["1.2.3.4"], "AAAA": [], "MX": ["10 mx.example."], "TXT": ["v=spf1 +all"], "DMARC": []}
    reg = {"registered": "2026-10-20T00:00:00Z", "expires": "2027-10-20", "status": ["client hold"]}
    text = " | ".join(f["level"] + ":" + f["text"] for f in domain.assess(rec, reg, today))
    assert "high:SPF ends in +all" in text
    assert "medium:No DMARC record" in text
    assert "high:Registered 5 days ago" in text
    assert "high:Registry status client hold" in text


def test_domain_failed_lookup_is_not_a_missing_record():
    assert domain.assess({}, None) == []


def test_domain_normalise():
    assert domain.normalise("https://www.Example.COM/path?x") == "example.com"
    assert domain.normalise("user@mail.example.org") == "mail.example.org"


def test_rdap_summary():
    d = {"events": [{"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"}],
         "entities": [{"roles": ["registrar"],
                       "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Reg AG"]]]}],
         "status": ["active"], "nameservers": [{"ldhName": "NS1.EXAMPLE"}]}
    s = domain.rdap_summary(d)
    assert s["registrar"] == "Reg AG" and s["registered"].startswith("2020") and s["nameservers"] == ["ns1.example"]


# ---------- ip

@pytest.mark.parametrize("addr,kind", [("192.168.1.10", "private"), ("127.0.0.1", "loopback"), ("8.8.8.8", "public"),
                                        ("[2001:4860:4860::8888]", "public"), ("fe80::1", "link-local")])
def test_ip_classify(addr, kind):
    assert ip.classify(addr)["kind"] == kind


def test_private_ip_needs_no_network():
    r = ip.run("10.1.2.3")
    assert "registry" not in r and "not on the internet" in r["findings"][0]["text"]


def test_ip_rdap_abuse_contact_in_nested_entity():
    d = {"name": "NET-1", "startAddress": "198.51.100.0", "endAddress": "198.51.100.255",
         "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Host GmbH"]]],
                       "entities": [{"roles": ["abuse"],
                                     "vcardArray": ["vcard", [["email", {}, "text", "abuse@host.example"]]]}]}]}
    s = ip.rdap_summary(d)
    assert s["owner"] == "Host GmbH" and s["abuse_email"] == "abuse@host.example"
