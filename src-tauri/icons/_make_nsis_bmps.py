"""Generate NSIS installer branding BMPs from the ViharaOS logo.

Outputs (24-bit BMP, NSIS-compatible):
  - nsis-header.bmp     150 x 57    (top-right banner)
  - nsis-sidebar.bmp    164 x 314   (welcome screen left panel)

Run:  python _make_nsis_bmps.py
"""
from PIL import Image, ImageDraw, ImageFilter

# Brand saffron-500 = rgb(255, 125, 10), saffron-600 = rgb(240, 93, 0)
SAFFRON_500 = (255, 125, 10)
SAFFRON_600 = (240, 93, 0)
SAFFRON_700 = (199, 67, 2)
INK = (28, 25, 23)       # near-black for text
PAPER = (252, 250, 247)  # warm off-white

LOGO_PATH = "icon.png"
OUT_HEADER = "nsis-header.bmp"
OUT_SIDEBAR = "nsis-sidebar.bmp"

logo = Image.open(LOGO_PATH).convert("RGBA")


def save_bmp(img: Image.Image, path: str) -> None:
    """Save as 24-bit BMP (BGR, no alpha) — NSIS-friendly."""
    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGB")
    img.save(path, format("BMP"), bits=24, compression=0)


# ---------------------------------------------------------------------------
# Header: 150x57. Small banner — saffron gradient with the logo mark on the
# left and "ViharaOS" wordmark on the right.
# ---------------------------------------------------------------------------
header = Image.new("RGB", (150, 57), SAFFRON_600)
hd = ImageDraw.Draw(header)
# Diagonal saffron gradient (cheap: a few stacked rectangles)
for i in range(150):
    t = i / 150.0
    r = int(SAFFRON_500[0] * (1 - t) + SAFFRON_700[0] * t)
    g = int(SAFFRON_500[1] * (1 - t) + SAFFRON_700[1] * t)
    b = int(SAFFRON_500[2] * (1 - t) + SAFFRON_700[2] * t)
    hd.line([(i, 0), (i, 57)], fill=(r, g, b))

# Logo mark, scaled to ~42px, dropped on the left with a soft white halo
mark = logo.resize((42, 42), Image.LANCZOS)
# White rounded halo behind the mark
halo = Image.new("RGBA", (48, 48), (0, 0, 0, 0))
hd2 = ImageDraw.Draw(halo)
hd2.rounded_rectangle([0, 0, 47, 47], radius=12, fill=(255, 255, 255, 235))
header.paste(halo, (7, 7), halo)
header.paste(mark, (10, 10), mark)

# Wordmark
hd.text((58, 18), "ViharaOS", fill=(255, 255, 255))
hd.text((58, 34), "Hotel PMS", fill=(255, 235, 210))

save_bmp(header, OUT_HEADER)
print(f"wrote {OUT_HEADER}  150x57")


# ---------------------------------------------------------------------------
# Sidebar: 164x314. Tall welcome panel — saffron vertical gradient with a
# large centered logo and the product name beneath.
# ---------------------------------------------------------------------------
sidebar = Image.new("RGB", (164, 314), SAFFRON_600)
sd = ImageDraw.Draw(sidebar)
for y in range(314):
    t = y / 314.0
    r = int(SAFFRON_500[0] * (1 - t) + SAFFRON_700[0] * t)
    g = int(SAFFRON_500[1] * (1 - t) + SAFFRON_700[1] * t)
    b = int(SAFFRON_500[2] * (1 - t) + SAFFRON_700[2] * t)
    sd.line([(0, y), (164, y)], fill=(r, g, b))

# Soft white halo + large logo mark, centered
mark_big = logo.resize((110, 110), Image.LANCZOS)
halo_big = Image.new("RGBA", (124, 124), (0, 0, 0, 0))
hd3 = ImageDraw.Draw(halo_big)
hd3.rounded_rectangle([0, 0, 123, 123], radius=28, fill=(255, 255, 255, 225))
sidebar.paste(halo_big, (20, 70), halo_big)
sidebar.paste(mark_big, (27, 77), mark_big)

# Wordmark + tagline
sd.text((82, 205), "ViharaOS", anchor="mm", fill=(255, 255, 255))
sd.text((82, 230), "Hotel Management", anchor="mm", fill=(255, 235, 210))
sd.text((82, 250), "System", anchor="mm", fill=(255, 235, 210))

save_bmp(sidebar, OUT_SIDEBAR)
print(f"wrote {OUT_SIDEBAR}  164x314")
