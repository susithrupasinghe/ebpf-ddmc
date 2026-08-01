#!/usr/bin/env python3
"""
EDDMC Evaluation — Chapter 6 data extraction, Task 4.

Renders real captured CLI output (raw stdout from `eddmc status` / `watch`
/ `alerts` against the live daemon, saved verbatim to /tmp/eddmc_screenshot_run/
during this session) into readable terminal-style PNGs, since no GUI
screenshot tool (scrot/import/gnome-screenshot) is installed in this
environment to capture an actual terminal window. Every character rendered
is copied from the real captured output -- this is a faithful
re-typesetting of a real command's real output, not a mockup.

Redaction: none of the three captures contain a hostname, username, IP
address, or wallet string (checked directly -- the process tables show only
comm/pid/score fields, and the alert reasons are the scorer's own templated
text). Nothing was redacted because nothing sensitive was present.
"""

import os
import re

from PIL import Image, ImageDraw, ImageFont

RUN_DIR = "/tmp/eddmc_screenshot_run"
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")

BG = (18, 18, 20)
FG = (222, 222, 222)
ANSI_COLORS = {
    "31": (230, 90, 90),   # red    -- CRITICAL
    "33": (235, 160, 60),  # orange -- HIGH
    "93": (235, 195, 60),  # yellow -- MEDIUM
    "96": (90, 205, 205),  # cyan   -- LOW
}

FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
]


def _font(size=20):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _parse_ansi_line(line):
    """Split a line into (text, color) segments, consuming \\x1b[NNm codes."""
    segments = []
    current_color = FG
    buf = ""
    i = 0
    while i < len(line):
        m = re.match(r"\x1b\[(\d*)m", line[i:])
        if m:
            if buf:
                segments.append((buf, current_color))
                buf = ""
            code = m.group(1)
            current_color = ANSI_COLORS.get(code, FG) if code and code != "0" else FG
            i += m.end()
            continue
        # Screen-clear / cursor-home codes -- drop, no visible effect on a static image.
        m2 = re.match(r"\x1b\[\d*[JH]", line[i:])
        if m2:
            i += m2.end()
            continue
        buf += line[i]
        i += 1
    if buf:
        segments.append((buf, current_color))
    return segments


def render(txt_path, out_name, pad=24, font_size=20, line_height=28):
    with open(txt_path, "r") as f:
        lines = f.read().splitlines()

    font = _font(font_size)
    tmp_img = Image.new("RGB", (10, 10))
    tmp_draw = ImageDraw.Draw(tmp_img)
    max_width = 0
    parsed = [_parse_ansi_line(l) for l in lines]
    for segs in parsed:
        line_text = "".join(s[0] for s in segs)
        bbox = tmp_draw.textbbox((0, 0), line_text or " ", font=font)
        max_width = max(max_width, bbox[2] - bbox[0])

    width = max_width + pad * 2
    height = line_height * len(parsed) + pad * 2
    img = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(img)

    y = pad
    for segs in parsed:
        x = pad
        for text, color in segs:
            if text:
                draw.text((x, y), text, font=font, fill=color)
                bbox = draw.textbbox((0, 0), text, font=font)
                x += bbox[2] - bbox[0]
        y += line_height

    out_path = os.path.join(OUT_DIR, out_name)
    img.save(out_path)
    print(f"[screenshots] wrote {out_path} ({width}x{height})")


if __name__ == "__main__":
    render(os.path.join(RUN_DIR, "status.txt"), "screenshot_eddmc_status.png", font_size=22, line_height=32)
    render(os.path.join(RUN_DIR, "watch.txt"), "screenshot_scored_process_list.png")
    render(os.path.join(RUN_DIR, "alerts.txt"), "screenshot_medium_alert_breakdown.png")
