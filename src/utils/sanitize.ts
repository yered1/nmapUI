import DOMPurify from 'dompurify';

const ALLOWED_TAGS = [
  'p', 'br', 'strong', 'em', 'u', 's', 'h1', 'h2', 'h3',
  'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'img', 'hr', 'span', 'mark',
];

const ALLOWED_ATTR = ['src', 'alt', 'class', 'color', 'data-color'];

// Register a hook once to strip non-data:image/ src attributes,
// preventing network requests to attacker-controlled URLs via <img>.
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'IMG') {
    const src = node.getAttribute('src') || '';
    // Allow data:image/ URIs except SVG (which can contain embedded scripts)
    if (!src.startsWith('data:image/') || src.startsWith('data:image/svg')) {
      node.removeAttribute('src');
    }
  }
});

/**
 * Sanitize HTML content for safe rendering via dangerouslySetInnerHTML.
 * Only allows rich-text formatting tags and data:image/ src attributes.
 */
export function sanitizeNoteHtml(html: string): string {
  return DOMPurify.sanitize(html, { ALLOWED_TAGS, ALLOWED_ATTR });
}
