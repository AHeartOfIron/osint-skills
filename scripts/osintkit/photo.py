"""Photo metadata: read EXIF (camera, dates, GPS) from JPEG, PNG and WebP, and strip it from JPEG and PNG."""

from __future__ import annotations

import struct
import zlib

IFD0_TAGS = {0x010E: "description", 0x010F: "make", 0x0110: "model", 0x0131: "software", 0x0132: "modified",
             0x013B: "artist", 0x8298: "copyright", 0x0112: "orientation"}
EXIF_TAGS = {0x9003: "taken", 0x9004: "digitized", 0x9011: "utc_offset", 0xA430: "owner", 0xA431: "serial",
             0xA434: "lens", 0xA420: "image_id", 0xA433: "lens_make"}
GPS_TAGS = {1: "lat_ref", 2: "lat", 3: "lon_ref", 4: "lon", 5: "alt_ref", 6: "alt", 7: "time", 0x1D: "date",
            0x11: "direction"}
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _read_ifd(t: bytes, off: int, bo: str) -> tuple[dict[int, object], int]:
    if off + 2 > len(t):
        return {}, 0
    (count,) = struct.unpack_from(bo + "H", t, off)
    tags: dict[int, object] = {}
    for i in range(min(count, 500)):
        e = off + 2 + 12 * i
        if e + 12 > len(t):
            break
        tag, typ, n = struct.unpack_from(bo + "HHI", t, e)
        size = TYPE_SIZE.get(typ)
        if not size:
            continue
        where = e + 8 if size * n <= 4 else struct.unpack_from(bo + "I", t, e + 8)[0]
        raw = t[where: where + size * n]
        if len(raw) < size * n:
            continue
        if typ == 2:
            val: object = raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()
        elif typ in (1, 7):
            val = raw.decode("utf-8", "replace").strip("\0 ") if typ == 7 and tag in (0xA420,) else list(raw)
        elif typ == 3:
            val = list(struct.unpack_from(bo + "H" * n, raw))
        elif typ in (4, 9):
            val = list(struct.unpack_from(bo + ("I" if typ == 4 else "i") * n, raw))
        else:
            nums = struct.unpack_from(bo + ("II" if typ == 5 else "ii") * n, raw)
            val = [a / b if b else 0.0 for a, b in zip(nums[::2], nums[1::2])]
        if isinstance(val, list) and len(val) == 1 and typ != 5:
            val = val[0]
        tags[tag] = val
    nxt_at = off + 2 + 12 * count
    nxt = struct.unpack_from(bo + "I", t, nxt_at)[0] if nxt_at + 4 <= len(t) else 0
    return tags, nxt


def parse_tiff(t: bytes) -> dict:
    """EXIF is a small TIFF file: IFD0, then pointers to the EXIF and GPS directories."""
    if t[:2] not in (b"II", b"MM"):
        return {}
    bo = "<" if t[:2] == b"II" else ">"
    (ifd0,) = struct.unpack_from(bo + "I", t, 4)
    base, _ = _read_ifd(t, ifd0, bo)
    out = {name: base[k] for k, name in IFD0_TAGS.items() if k in base}
    if isinstance(ptr := base.get(0x8769), int):
        ex, _ = _read_ifd(t, ptr, bo)
        out.update({name: ex[k] for k, name in EXIF_TAGS.items() if k in ex})
    if isinstance(ptr := base.get(0x8825), int):
        gps, _ = _read_ifd(t, ptr, bo)
        g = {name: gps[k] for k, name in GPS_TAGS.items() if k in gps}
        if g:
            out["gps_raw"] = g
    return out


def _dms(v, ref) -> float | None:
    if not isinstance(v, list) or len(v) != 3:
        return None
    deg = v[0] + v[1] / 60 + v[2] / 3600
    return round(-deg if str(ref).upper() in ("S", "W") else deg, 7)


def gps(raw: dict) -> dict | None:
    lat, lon = _dms(raw.get("lat"), raw.get("lat_ref")), _dms(raw.get("lon"), raw.get("lon_ref"))
    if lat is None or lon is None or (lat == 0 and lon == 0):
        return None
    out = {"lat": lat, "lon": lon, "map": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"}
    alt = raw.get("alt")
    if isinstance(alt, list) and alt:
        out["altitude_m"] = round(-alt[0] if raw.get("alt_ref") == [1] or raw.get("alt_ref") == 1 else alt[0], 1)
    if raw.get("date"):
        out["fix_date"] = raw["date"]
    return out


def jpeg_segments(data: bytes):
    """(marker, start, end) of each segment before the image data starts."""
    if data[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            raise ValueError(f"broken JPEG segment at byte {i}")
        marker = data[i + 1]
        if marker == 0xDA:  # start of scan: compressed image follows
            yield marker, i, None
            return
        (length,) = struct.unpack_from(">H", data, i + 2)
        yield marker, i, i + 2 + length
        i += 2 + length


def png_chunks(data: bytes):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    i = 8
    while i + 8 <= len(data):
        (n,) = struct.unpack_from(">I", data, i)
        yield data[i + 4: i + 8].decode("latin-1"), i, i + 12 + n
        i += 12 + n


def read(data: bytes) -> dict:
    out: dict = {"format": None, "exif": {}, "other": {}}
    if data[:2] == b"\xff\xd8":
        out["format"] = "jpeg"
        for marker, s, e in jpeg_segments(data):
            if e is None:
                break
            payload = data[s + 4: e]
            if marker == 0xE1 and payload.startswith(b"Exif\0\0"):
                out["exif"] = parse_tiff(payload[6:])
            elif marker == 0xE1 and payload.startswith(b"http://ns.adobe.com/xap/"):
                out["other"]["xmp"] = True
            elif marker == 0xED:
                out["other"]["iptc_photoshop"] = True
            elif marker == 0xFE:
                out["other"]["comment"] = payload.decode("utf-8", "replace").strip("\0 ")
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        out["format"] = "png"
        text = {}
        for typ, s, e in png_chunks(data):
            body = data[s + 8: e - 4]
            if typ == "eXIf":
                out["exif"] = parse_tiff(body)
            elif typ == "tEXt" and b"\0" in body:
                k, v = body.split(b"\0", 1)
                text[k.decode("latin-1")] = v.decode("latin-1")[:500]
            elif typ == "zTXt" and b"\0" in body:
                k, v = body.split(b"\0", 1)
                try:
                    text[k.decode("latin-1")] = zlib.decompress(v[1:]).decode("latin-1")[:500]
                except zlib.error:
                    text[k.decode("latin-1")] = "(unreadable)"
            elif typ == "iTXt":
                text[body.split(b"\0", 1)[0].decode("latin-1")] = "(international text)"
        if text:
            out["other"]["text"] = text
    elif data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        out["format"] = "webp"
        i = 12
        while i + 8 <= len(data):
            fourcc, n = data[i: i + 4], struct.unpack_from("<I", data, i + 4)[0]
            body = data[i + 8: i + 8 + n]
            if fourcc == b"EXIF":
                out["exif"] = parse_tiff(body[6:] if body.startswith(b"Exif\0\0") else body)
            elif fourcc == b"XMP ":
                out["other"]["xmp"] = True
            i += 8 + n + (n & 1)
    else:
        raise ValueError("unsupported format: JPEG, PNG and WebP only (for HEIC and RAW, use exiftool)")

    ex = out["exif"]
    if "gps_raw" in ex:
        out["gps"] = gps(ex.pop("gps_raw"))
    out["findings"] = assess(out)
    return out


def assess(r: dict) -> list[dict]:
    f: list[dict] = []
    add = lambda level, text: f.append({"level": level, "text": text})
    ex = r["exif"]
    if r.get("gps"):
        g = r["gps"]
        add("high", f"The photo holds an exact location: {g['lat']}, {g['lon']}. Anyone with the file can see where it was taken.")
    if ex.get("serial") or ex.get("owner"):
        add("medium", "Camera serial number or owner name is stored. It can link different photos to one camera or person.")
    if ex.get("artist") or ex.get("copyright"):
        add("info", f"Author fields: {ex.get('artist') or ''} {ex.get('copyright') or ''}".strip())
    if ex.get("software"):
        add("info", f"Saved by software: {ex['software']}. Editing software does not prove the content was changed.")
    if ex.get("taken") and ex.get("modified") and ex["taken"] != ex["modified"]:
        add("info", f"Taken {ex['taken']}, last saved {ex['modified']}.")
    if not ex and not r["other"]:
        add("info", "No metadata. Messengers and social networks usually remove it, so its absence proves nothing.")
    elif ex.get("taken"):
        add("info", "Camera dates come from the device clock. They can be wrong or set by hand.")
    return f


KEEP_JPEG = {0xE0, 0xE2, 0xEE}  # JFIF, ICC colour profile, Adobe colour transform


def strip(data: bytes) -> bytes:
    """A copy without EXIF, XMP, IPTC and comments. The pixels are not re-encoded."""
    if data[:2] == b"\xff\xd8":
        parts = [b"\xff\xd8"]
        for marker, s, e in jpeg_segments(data):
            if e is None:
                parts.append(data[s:])
                break
            if 0xE0 <= marker <= 0xEF and marker not in KEEP_JPEG or marker == 0xFE:
                continue
            parts.append(data[s:e])
        return b"".join(parts)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        parts = [data[:8]]
        for typ, s, e in png_chunks(data):
            if typ not in ("tEXt", "zTXt", "iTXt", "eXIf", "tIME"):
                parts.append(data[s:e])
        return b"".join(parts)
    raise ValueError("stripping supports JPEG and PNG only")
