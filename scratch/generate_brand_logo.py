"""
Generate professional corporate brand logos for VeriDex AI.
Creates clean, geometric, non-emoji vector and high-res raster assets.
"""

import os
from PIL import Image, ImageDraw, ImageFont

ASSETS_DIR = r"C:\Users\SHREYA S\veridex-engine\ui\web\assets"
os.makedirs(ASSETS_DIR, exist_ok=True)

# Crema Palette
BG_CREMA = (250, 248, 245)       # #FAF8F5
ESPRESSO = (36, 30, 25)          # #241E19
BRONZE = (140, 104, 66)          # #8C6842
BRONZE_LIGHT = (184, 144, 101)   # #B89065
ACCENT_SAGE = (43, 110, 78)      # #2B6E4E

def create_geometric_logo_mark(size=512):
    """
    Creates a high-resolution, sharp geometric 'V' brandmark.
    Uses multi-faceted precision angles (anti-aliased by rendering at 4x supersampling).
    """
    scale = 4
    canvas_size = size * scale
    img = Image.new("RGBA", (canvas_size, canvas_size), (250, 248, 245, 255))
    draw = ImageDraw.Draw(img)

    cx = canvas_size // 2
    cy = canvas_size // 2
    w = int(canvas_size * 0.65)
    h = int(canvas_size * 0.65)

    # Coords relative to bounding box
    top_y = cy - h // 2
    bot_y = cy + h // 2
    left_x = cx - w // 2
    right_x = cx + w // 2

    # Left main chevron facet (Espresso)
    poly_left = [
        (left_x, top_y),
        (left_x + int(w * 0.38), top_y),
        (cx, bot_y - int(h * 0.22)),
        (cx, bot_y),
    ]
    draw.polygon(poly_left, fill=(36, 30, 25, 255))

    # Right interlocking diagonal facet (Warm Bronze)
    poly_right = [
        (right_x, top_y),
        (right_x - int(w * 0.38), top_y),
        (cx, bot_y - int(h * 0.22)),
        (cx + int(w * 0.16), bot_y - int(h * 0.38)),
    ]
    draw.polygon(poly_right, fill=(140, 104, 66, 255))

    # Dynamic apex accent wedge (Refined Bronze Accent)
    poly_accent = [
        (cx - int(w * 0.08), top_y + int(h * 0.42)),
        (cx + int(w * 0.12), top_y + int(h * 0.42)),
        (cx, bot_y),
        (cx - int(w * 0.08), bot_y - int(h * 0.12)),
    ]
    draw.polygon(poly_accent, fill=(184, 144, 101, 255))

    # Downsample to target size with high-quality Lanczos resampling
    img_final = img.resize((size, size), Image.Resampling.LANCZOS)
    return img_final

def create_full_horizontal_logo(width=800, height=220):
    """Creates full horizontal lockup with logo mark + clean typography."""
    img = Image.new("RGBA", (width, height), (250, 248, 245, 255))
    mark = create_geometric_logo_mark(size=140)
    
    # Paste mark on left
    img.paste(mark, (40, (height - 140) // 2))
    
    draw = ImageDraw.Draw(img)
    
    # Try to load high quality font, fallback to default
    try:
        font_large = ImageFont.truetype("arial.ttf", 52)
        font_small = ImageFont.truetype("arial.ttf", 22)
    except:
        font_large = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # Draw Text
    draw.text((210, 60), "VERIDEX", fill=(36, 30, 25, 255), font=font_large)
    
    # Draw "AI" badge
    # Draw pill background for AI
    ai_box = [460, 64, 525, 114]
    draw.rounded_rectangle(ai_box, radius=8, fill=(140, 104, 66, 255))
    try:
        font_ai = ImageFont.truetype("arial.ttf", 32)
    except:
        font_ai = font_large
    draw.text((474, 71), "AI", fill=(250, 248, 245, 255), font=font_ai)

    # Subtitle
    draw.text((212, 128), "AUTONOMOUS ON-DEVICE SCAM PROTECTION", fill=(117, 106, 99, 255), font=font_small)

    return img

if __name__ == "__main__":
    logo_mark = create_geometric_logo_mark(512)
    logo_mark_path = os.path.join(ASSETS_DIR, "logo.png")
    logo_mark.save(logo_mark_path, "PNG")
    print(f"Saved logo mark: {logo_mark_path}")

    logo_full = create_full_horizontal_logo(800, 220)
    logo_full_path = os.path.join(ASSETS_DIR, "logo_full.png")
    logo_full.save(logo_full_path, "PNG")
    print(f"Saved full logo: {logo_full_path}")
