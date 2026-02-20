"""
generate_icons.py — Generate VerifyFirst extension icons as PNG files.

Run:
    python generate_icons.py

Outputs:
    extension/icons/icon16.png
    extension/icons/icon48.png
    extension/icons/icon128.png

No external dependencies — uses only stdlib (struct, zlib).
"""

import os
import struct
import zlib

ICON_DIR = os.path.join(os.path.dirname(__file__), "extension", "icons")


def write_png(path: str, size: int) -> None:
    """Write a minimal PNG icon with VerifyFirst branding (shield-like design)."""

    # Build RGBA pixel data
    pixels = []
    cx, cy = size / 2, size / 2
    r = size / 2 - 1

    # Colors
    BG        = (0,   10,  24, 0)    # transparent bg
    RED       = (229, 20,  75, 255)  # accent red
    RED_DARK  = (120, 10,  40, 255)  # darker rim
    WHITE     = (220, 232, 245, 255) # shield inner

    for y in range(size):
        row = []
        for x in range(size):
            dx = x - cx
            dy = y - cy
            dist = (dx*dx + dy*dy) ** 0.5

            # Shield shape: slightly taller ellipse, clipped at bottom-center
            # Parametric shield: wider at top, narrows to point at bottom
            norm_y = (y - 1) / (size - 2)   # 0 = top, 1 = bottom
            half_w_ratio = 0.48 * (1.0 - 0.65 * (norm_y ** 2))
            half_w = half_w_ratio * size
            in_shield_x = abs(dx) < half_w

            # Vertical bounds
            in_shield_y = (y >= size * 0.06) and (y <= size * 0.94)

            if in_shield_x and in_shield_y:
                edge_dist = min(
                    abs(dx) - half_w,          # left/right edge (negative = inside)
                    (y - size * 0.06),
                    (size * 0.94 - y),
                    half_w - abs(dx),
                )
                rim_thickness = max(1, size / 12)

                if half_w - abs(dx) < rim_thickness or y - size * 0.06 < rim_thickness:
                    # Rim
                    row.append(RED_DARK)
                else:
                    # Inner fill — add V mark for sizes >= 32
                    in_v = False
                    if size >= 32:
                        v_cx = cx
                        v_top_y = size * 0.28
                        v_bot_y = size * 0.68
                        v_arm_w = size * 0.28
                        t = (y - v_top_y) / (v_bot_y - v_top_y)
                        if 0 <= t <= 1:
                            # Left arm of V
                            if t <= 0.5:
                                expected_x = v_cx - v_arm_w * (1 - t * 2)
                            else:
                                expected_x = v_cx + v_arm_w * ((t - 0.5) * 2)
                            thick = max(1.5, size / 14)
                            if abs(x - expected_x) < thick:
                                in_v = True

                    if in_v:
                        row.append(RED)
                    else:
                        row.append(WHITE)
            else:
                row.append(BG)

        pixels.append(row)

    # Encode PNG
    png_data = _encode_png(pixels, size, size)
    with open(path, "wb") as f:
        f.write(png_data)

    print(f"  Written: {path}  ({size}×{size})")


def _encode_png(pixels, width, height):
    """Minimal RGBA PNG encoder using stdlib only."""

    def chunk(name: bytes, data: bytes) -> bytes:
        c = name + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    # IHDR
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    ihdr_chunk = chunk(b"IHDR", ihdr)

    # IDAT — raw image data (filter byte 0 per row)
    raw_rows = []
    for row in pixels:
        row_bytes = bytearray()
        row_bytes.append(0)  # filter type: none
        for r, g, b, a in row:
            row_bytes += bytes([r, g, b, a])
        raw_rows.append(bytes(row_bytes))

    compressed = zlib.compress(b"".join(raw_rows), level=6)
    idat_chunk = chunk(b"IDAT", compressed)

    # IEND
    iend_chunk = chunk(b"IEND", b"")

    signature = b"\x89PNG\r\n\x1a\n"
    return signature + ihdr_chunk + idat_chunk + iend_chunk


if __name__ == "__main__":
    os.makedirs(ICON_DIR, exist_ok=True)
    print("Generating VerifyFirst extension icons…")
    for size in (16, 48, 128):
        path = os.path.join(ICON_DIR, f"icon{size}.png")
        write_png(path, size)
    print("\nDone. Icons saved to extension/icons/")
