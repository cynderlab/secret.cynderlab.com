"""Generate the app brand assets: static/img/logo.png and static/img/og.png.

Run after changing brand colors or copy:  uv run python scripts/gen_og.py
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONTS = ROOT / "static" / "fonts"
IMG = ROOT / "static" / "img"

BG = "#0C1420"
PANEL = "#121D2E"
LINE = "#22334D"
CYAN = "#2CB9DD"
TEXT = "#DCE7F2"
MUTED = "#7E8FA6"
EMBER = "#FF8A3D"


def mono(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / "JetBrainsMono-Bold.ttf"), size)


def barlow(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONTS / "Barlow-Regular.ttf"), size)


def draw_tile(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int]) -> None:
    """The app mark: a dark tile with 's#' and one ember dot (reads left: 1)."""
    x0, y0, x1, y1 = box
    size = x1 - x0
    radius = size * 22 // 100
    draw.rounded_rectangle(box, radius=radius, fill=PANEL,
                           outline=LINE, width=max(2, size // 64))
    font = mono(size * 46 // 100)
    draw.text(((x0 + x1) / 2, (y0 + y1) / 2 + size * 3 // 100), "s#",
              font=font, fill=CYAN, anchor="mm")
    r = size * 9 // 100
    cx, cy = x1 - size * 22 // 100, y0 + size * 22 // 100
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=EMBER)


def gen_logo() -> None:
    img = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
    draw_tile(ImageDraw.Draw(img), (8, 8, 504, 504))
    img.save(IMG / "logo.png")


def gen_og() -> None:
    img = Image.new("RGB", (1200, 630), BG)
    d = ImageDraw.Draw(img)

    # Giant translucent "s#" bleeding off the right edge.
    ghost = Image.new("RGBA", (1200, 630), (0, 0, 0, 0))
    ImageDraw.Draw(ghost).text((1180, 315), "s#", font=mono(560),
                               fill=(44, 185, 221, 26), anchor="rm")
    img.paste(ghost, (0, 0), ghost)

    draw_tile(d, (90, 84, 232, 226))

    d.text((270, 118), "secret.cynderlab.com", font=mono(54), fill=TEXT, anchor="lm")
    d.text((270, 186), "by CYNDERLAB", font=barlow(30), fill=MUTED, anchor="lm")

    d.text((90, 330), "Share secrets that", font=mono(64), fill=TEXT, anchor="lm")
    d.text((90, 408), "self-destruct.", font=mono(64), fill=CYAN, anchor="lm")

    d.text((90, 500), "one link · one read · then ash", font=mono(30),
           fill=EMBER, anchor="lm")
    d.text((90, 556), "Encrypted in your browser — the server never sees the key.",
           font=barlow(28), fill=MUTED, anchor="lm")

    img.save(IMG / "og.png")


if __name__ == "__main__":
    gen_logo()
    gen_og()
    print(f"wrote {IMG / 'logo.png'} and {IMG / 'og.png'}")
