/**
 * Convert a port/host state string to a CSS-safe class suffix.
 * e.g., "open|filtered" → "open-filtered", "closed|filtered" → "closed-filtered"
 */
export function stateClass(state: string): string {
  return state.replace(/\|/g, '-');
}

/**
 * Format uptime seconds into human-readable string.
 */
export function formatUptime(seconds: number): string {
  if (!seconds) return 'N/A';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (mins > 0) parts.push(`${mins}m`);
  return parts.join(' ') || '< 1m';
}

/**
 * Copy text to clipboard. Works in both Electron and browser contexts.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers / restricted contexts
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  }
}

/**
 * Format a timestamp (seconds since epoch) to locale string.
 */
export function formatTimestamp(ts: number): string {
  if (!ts) return 'N/A';
  return new Date(ts * 1000).toLocaleString();
}
