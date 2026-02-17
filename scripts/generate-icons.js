#!/usr/bin/env node

/**
 * Generate application icons for electron-builder.
 *
 * electron-builder can auto-convert a 512x512 PNG into:
 *   - .icns (macOS)
 *   - .ico  (Windows)
 *   - Multiple sizes for Linux
 *
 * This script creates a 512x512 PNG using a minimal Canvas approach
 * that works without native dependencies. If `sharp` or `canvas` is
 * available it uses them; otherwise it falls back to writing a raw PNG
 * with the built-in zlib.
 *
 * Usage: node scripts/generate-icons.js
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZE = 512;
const OUT_DIR = path.join(__dirname, '..', 'build');

// Ensure output dir exists
if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

/**
 * Create a minimal valid PNG with a colored icon design.
 * This is a raw-pixel PNG encoder (no dependencies).
 */
function createPNG(width, height, drawFn) {
  // RGBA buffer
  const pixels = Buffer.alloc(width * height * 4, 0);

  // Let caller draw
  drawFn(pixels, width, height);

  // PNG encoding
  function crc32(buf) {
    let crc = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      crc ^= buf[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
      }
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const typeAndData = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(typeAndData));
    return Buffer.concat([len, typeAndData, crc]);
  }

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // IDAT: raw pixel data with filter byte per row
  const rawRows = [];
  for (let y = 0; y < height; y++) {
    rawRows.push(Buffer.from([0])); // filter: none
    rawRows.push(pixels.subarray(y * width * 4, (y + 1) * width * 4));
  }
  const rawData = Buffer.concat(rawRows);
  const compressed = zlib.deflateSync(rawData);

  // Assemble PNG
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', compressed),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function setPixel(pixels, w, x, y, r, g, b, a = 255) {
  x = Math.round(x);
  y = Math.round(y);
  if (x < 0 || x >= w || y < 0 || y >= w) return;
  const i = (y * w + x) * 4;
  // Alpha blend
  const srcA = a / 255;
  const dstA = pixels[i + 3] / 255;
  const outA = srcA + dstA * (1 - srcA);
  if (outA === 0) return;
  pixels[i]     = Math.round((r * srcA + pixels[i]     * dstA * (1 - srcA)) / outA);
  pixels[i + 1] = Math.round((g * srcA + pixels[i + 1] * dstA * (1 - srcA)) / outA);
  pixels[i + 2] = Math.round((b * srcA + pixels[i + 2] * dstA * (1 - srcA)) / outA);
  pixels[i + 3] = Math.round(outA * 255);
}

function fillCircle(pixels, w, cx, cy, radius, r, g, b, a = 255) {
  const r2 = radius * radius;
  for (let dy = -radius; dy <= radius; dy++) {
    for (let dx = -radius; dx <= radius; dx++) {
      if (dx * dx + dy * dy <= r2) {
        setPixel(pixels, w, cx + dx, cy + dy, r, g, b, a);
      }
    }
  }
}

function fillRoundedRect(pixels, w, x, y, rw, rh, radius, r, g, b, a = 255) {
  for (let py = y; py < y + rh; py++) {
    for (let px = x; px < x + rw; px++) {
      // Check corners
      let inside = true;
      if (px < x + radius && py < y + radius) {
        inside = (px - x - radius) ** 2 + (py - y - radius) ** 2 <= radius ** 2;
      } else if (px > x + rw - radius && py < y + radius) {
        inside = (px - x - rw + radius) ** 2 + (py - y - radius) ** 2 <= radius ** 2;
      } else if (px < x + radius && py > y + rh - radius) {
        inside = (px - x - radius) ** 2 + (py - y - rh + radius) ** 2 <= radius ** 2;
      } else if (px > x + rw - radius && py > y + rh - radius) {
        inside = (px - x - rw + radius) ** 2 + (py - y - rh + radius) ** 2 <= radius ** 2;
      }
      if (inside) setPixel(pixels, w, px, py, r, g, b, a);
    }
  }
}

function drawLine(pixels, w, x1, y1, x2, y2, r, g, b, a = 255, thickness = 2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const steps = Math.max(Math.abs(dx), Math.abs(dy)) * 2;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const px = x1 + dx * t;
    const py = y1 + dy * t;
    for (let tx = -thickness / 2; tx <= thickness / 2; tx++) {
      for (let ty = -thickness / 2; ty <= thickness / 2; ty++) {
        setPixel(pixels, w, px + tx, py + ty, r, g, b, a);
      }
    }
  }
}

function drawArc(pixels, w, cx, cy, radius, startAngle, endAngle, r, g, b, a, thickness) {
  const steps = Math.ceil(radius * Math.abs(endAngle - startAngle));
  for (let i = 0; i <= steps; i++) {
    const angle = startAngle + (endAngle - startAngle) * (i / steps);
    const px = cx + Math.cos(angle) * radius;
    const py = cy + Math.sin(angle) * radius;
    for (let tx = -thickness / 2; tx <= thickness / 2; tx++) {
      for (let ty = -thickness / 2; ty <= thickness / 2; ty++) {
        if (tx * tx + ty * ty <= (thickness / 2) ** 2) {
          setPixel(pixels, w, px + tx, py + ty, r, g, b, a);
        }
      }
    }
  }
}

const png = createPNG(SIZE, SIZE, (pixels, w, h) => {
  const cx = w / 2, cy = h / 2;

  // Background: rounded rect
  fillRoundedRect(pixels, w, 0, 0, w, h, 96, 15, 23, 42, 255);

  // Subtle glow in upper portion
  for (let y = 0; y < h / 2; y++) {
    const alpha = Math.round(30 * (1 - y / (h / 2)));
    for (let x = 0; x < w; x++) {
      // Check if within rounded rect
      const inCorner =
        (x < 96 && y < 96 && (x - 96) ** 2 + (y - 96) ** 2 > 96 ** 2) ||
        (x > w - 96 && y < 96 && (x - w + 96) ** 2 + (y - 96) ** 2 > 96 ** 2);
      if (!inCorner) {
        setPixel(pixels, w, x, y, 125, 211, 252, alpha);
      }
    }
  }

  // Network ring (outer)
  drawArc(pixels, w, cx, cy, 160, 0, Math.PI * 2, 56, 189, 248, 100, 6);
  // Inner ring
  drawArc(pixels, w, cx, cy, 110, 0, Math.PI * 2, 56, 189, 248, 50, 3);
  // Scanning arc highlight
  drawArc(pixels, w, cx, cy, 160, -Math.PI / 2, 0, 56, 189, 248, 255, 8);

  // Connection lines to nodes
  const nodes = [
    { x: cx, y: 96, r: 74, g: 222, b: 128 },   // top - green
    { x: 416, y: cy, r: 74, g: 222, b: 128 },   // right - green
    { x: cx, y: 416, r: 251, g: 191, b: 36 },   // bottom - yellow
    { x: 96, y: cy, r: 248, g: 113, b: 113 },   // left - red
    { x: 369, y: 143, r: 74, g: 222, b: 128 },  // top-right - green
    { x: 369, y: 369, r: 74, g: 222, b: 128 },  // bottom-right - green
    { x: 143, y: 369, r: 251, g: 191, b: 36 },  // bottom-left - yellow
    { x: 143, y: 143, r: 248, g: 113, b: 113 }, // top-left - red
  ];

  for (const node of nodes) {
    drawLine(pixels, w, cx, cy, node.x, node.y, node.r, node.g, node.b, 80, 2);
  }

  // Center node
  fillCircle(pixels, w, cx, cy, 24, 56, 189, 248);
  fillCircle(pixels, w, cx, cy, 12, 15, 23, 42);

  // Outer nodes
  for (let i = 0; i < 4; i++) {
    fillCircle(pixels, w, nodes[i].x, nodes[i].y, 14, nodes[i].r, nodes[i].g, nodes[i].b);
  }
  for (let i = 4; i < 8; i++) {
    fillCircle(pixels, w, nodes[i].x, nodes[i].y, 10, nodes[i].r, nodes[i].g, nodes[i].b);
  }
});

const outPath = path.join(OUT_DIR, 'icon.png');
fs.writeFileSync(outPath, png);
console.log(`Generated ${outPath} (${png.length} bytes)`);

// electron-builder will auto-convert icon.png → icon.icns (macOS) and icon.ico (Windows)
// For Linux, it reads PNGs from the build/ directory
console.log('electron-builder will auto-convert to .icns and .ico during build');
