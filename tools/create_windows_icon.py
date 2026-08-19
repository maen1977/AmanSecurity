from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "windows" / "MaenShield.Installer" / "MaenShield.ico"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def make_icon(size: int) -> Image.Image:
    scale = size / 256.0
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def xy(values):
        return tuple(round(v * scale) for v in values)

    # Soft rounded navy tile keeps the icon legible in Explorer and the taskbar.
    margin = max(2, round(18 * scale))
    radius = max(2, round(42 * scale))
    draw.rounded_rectangle((margin, margin, size - margin, size - margin), radius=radius, fill=(10, 29, 50, 255))

    # Shield silhouette.
    shield = [xy((128, 42)), xy((205, 72)), xy((198, 142)), xy((169, 190)), xy((128, 218)), xy((87, 190)), xy((58, 142)), xy((51, 72))]
    draw.polygon(shield, fill=(22, 119, 210, 255))
    inner = [xy((128, 59)), xy((187, 83)), xy((181, 137)), xy((157, 174)), xy((128, 194)), xy((99, 174)), xy((75, 137)), xy((69, 83))]
    draw.polygon(inner, fill=(244, 247, 251, 255))

    # Safe-status check mark.
    width = max(2, round(18 * scale))
    points = [xy((92, 128)), xy((116, 153)), xy((168, 98))]
    draw.line(points, fill=(25, 137, 91, 255), width=width, joint="curve")
    # Round endpoints for small icon sizes.
    endpoint = max(1, round(width / 2))
    for x, y in (points[0], points[-1]):
        draw.ellipse((x - endpoint, y - endpoint, x + endpoint, y + endpoint), fill=(25, 137, 91, 255))
    return image


OUT.parent.mkdir(parents=True, exist_ok=True)
images = [make_icon(size) for size in SIZES]
images[-1].save(OUT, format="ICO", sizes=[(im.width, im.height) for im in images], append_images=images[:-1])
print(OUT)
