#!/usr/bin/env python3
"""osint-skills command line. Prints JSON for Claude (or you) to read.

    python osint.py domain example.com [--subdomains]
    python osint.py email message.eml          (or: ... email - < headers.txt)
    python osint.py photo IMG_0001.jpg [--strip clean.jpg]
    python osint.py link "https://bit.ly/x" "tg://msg_url?url=..." [--expand]
    python osint.py ip 203.0.113.7 [--tor]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from osintkit import domain, email_headers, ip, links, photo  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="osint.py", description="Defensive OSINT checks. Standard library only.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("domain", help="DNS, SPF/DMARC, registration, optional subdomains")
    p.add_argument("name")
    p.add_argument("--subdomains", action="store_true", help="also list names from certificate logs (crt.sh, slow)")
    p = sub.add_parser("email", help="analyse raw headers of a message")
    p.add_argument("file", help=".eml or text file with the headers, or - for stdin")
    p = sub.add_parser("photo", help="read metadata of a JPEG, PNG or WebP")
    p.add_argument("file")
    p.add_argument("--strip", metavar="OUT", help="write a copy without metadata (JPEG, PNG)")
    p = sub.add_parser("link", help="what a link really opens")
    p.add_argument("urls", nargs="+")
    p.add_argument("--expand", action="store_true", help="follow redirects (contacts each server, downloads nothing)")
    p = sub.add_parser("ip", help="owner, abuse contact and type of an IP address")
    p.add_argument("address")
    p.add_argument("--tor", action="store_true", help="also check the Tor exit list")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "domain":
            result = domain.run(a.name, a.subdomains)
        elif a.cmd == "email":
            raw = sys.stdin.buffer.read() if a.file == "-" else Path(a.file).read_bytes()
            result = email_headers.analyse(raw)
        elif a.cmd == "photo":
            data = Path(a.file).read_bytes()
            result = photo.read(data)
            if a.strip:
                src, dst = Path(a.file).resolve(), Path(a.strip).resolve()
                if src == dst:
                    raise ValueError("--strip must name a new file; the original is never overwritten")
                dst.write_bytes(photo.strip(data))
                result["stripped_copy"] = str(dst)
                result["stripped_left"] = photo.read(dst.read_bytes())["exif"]
        elif a.cmd == "link":
            result = links.run(a.urls, a.expand)
        else:
            result = ip.run(a.address, a.tor)
    except (ValueError, OSError) as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
