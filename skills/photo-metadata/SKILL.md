---
name: photo-metadata
description: >
  Read hidden metadata in photos (GPS location, camera, serial number, dates,
  editing software, comments) from JPEG, PNG and WebP, and make a clean copy
  without it. Use when the user asks what a photo reveals, wants to check
  where or when a picture was taken, or wants to remove location data before
  publishing or sending a photo.
---

# Photo metadata

## Run

```bash
python3 "<base>/../../scripts/osint.py" photo IMG_1234.jpg
python3 "<base>/../../scripts/osint.py" photo IMG_1234.jpg --strip IMG_1234_clean.jpg
```

`<base>` is this skill's base directory. On Windows use `py` or `python`.
Offline: the file never leaves the machine.

- `--strip` writes a NEW file. The original is never changed. It removes EXIF
  (including GPS), XMP, IPTC and comments from JPEG and PNG. Pixels are copied,
  not re-encoded, so quality is identical.
- After stripping, `stripped_left` shows what is still in the copy. It should be `{}`.

## Read the result

`exif` (make, model, software, taken, modified, serial, owner, lens...),
`gps` (lat, lon, altitude, an OpenStreetMap link), `other` (XMP, IPTC,
comments, PNG text), `findings`.

## Tell the user

1. Lead with location: if `gps` is present, say plainly that the file shows
   where it was taken, and give the map link.
2. Mention serial numbers or owner names: they tie photos to one device or person.
3. Missing metadata proves nothing. WhatsApp, Telegram, Signal, Instagram and
   most sites remove it on upload. Original files from a phone usually keep it.
4. Camera dates come from the device clock and can be wrong or edited.
5. Offer `--strip` before the user publishes or sends an original file.

## Limits and ethics

- HEIC, RAW and video are not supported: suggest `exiftool` for those.
- Stripping drops the orientation tag, so a few phone photos may show rotated.
- Use this to protect people and to verify material. Do not use it to locate a
  private person who did not choose to share where they are.
