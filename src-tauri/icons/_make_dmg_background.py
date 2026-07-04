"""Generate the macOS DMG background image (660x400 PNG).

A soft saffron radial gradient with the ViharaOS logo mark in the upper-left
and a hint to drag the app to Applications on the right.

Run:  python _make_dmg_background.py
"""
from PIL import Image, ImageDraw, ImageFilter

SAFFRON_500 = (255, 125, 10)
SAFFRON_600 = (240, 93, 0)
SAFFRON_700 = (199, 67, 2)
PAPER = (252, 250, 247)

W, H = 660, 400
img = Image.new("RGB", (W, H), PAPER)
px = img.load()

# Soft radial saffron glow centered upper-left
for y in range(H):
    for x in range(W):
        dx = (x - 180) / 240.0
        dy = (y - 140) / 240.0
        d = (dx * dx + dy * dy) ** 0.5
        if d < 1.0:
            t = d
            r = int(SAFFRON_500[0] * (1 - t) + PAPER[0] * t)
            g = int(SAFFRON_500[1] * (1 - t) + PAPER[1] * t)
            b = int(SAFFRON_500[2] * (1 - t) + PAPER[2] * t)
            px[x, y] = (r, g, b)

img = img.filter(ImageFilter.GaussianBlur(radius=40))

# Logo mark in upper-left
logo = Image.open("icon.png").convert("RGBA")
mark = logo.resize((96, 96), Image.LANCZOS)
halo = Image.new("RGBA", (108, 108), (0, 0, 0, 0))
hd = ImageDraw.Draw(halo)
hd.rounded_rectangle([0, 0, 107, 107], radius=24, fill=(255, 255, 255, 230))
img.paste(halo, (126, 92), halo)
img.paste(mark, (132, 98), mark)

# Wordmark
d = ImageDraw.Draw(img)
d.text((246, 122), "ViharaOS", fill=(60, 50, 40))
d.text((246, 150), "Hotel Management System", fill=(120, 100, 80))

# Drag hint near the app icon position (right side)
d.text((440, 196), "Drag to", fill=(120, 100, 80))
d.text((440, 214), "Applications", fill=(120, 100, 80))

img.save("dmg-background.png", "PNG")
print("wrote dmg-background.png  660x400")
