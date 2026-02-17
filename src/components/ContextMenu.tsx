import React, { useEffect, useRef } from 'react';

export interface ContextMenuItem {
  label: string;
  action: () => void;
  disabled?: boolean;
  separator?: boolean;
}

interface ContextMenuProps {
  x: number;
  y: number;
  items: ContextMenuItem[];
  onClose: () => void;
}

export function ContextMenu({ x, y, items, onClose }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [onClose]);

  // Adjust position to stay within viewport
  const adjustedX = Math.min(x, window.innerWidth - 200);
  const adjustedY = Math.min(y, window.innerHeight - items.length * 32 - 16);

  return (
    <div
      ref={ref}
      role="menu"
      aria-label="Context menu"
      style={{
        position: 'fixed',
        left: adjustedX,
        top: adjustedY,
        zIndex: 2000,
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-md)',
        boxShadow: 'var(--shadow-lg)',
        padding: '4px 0',
        minWidth: 180,
      }}
    >
      {items.map((item, i) => {
        if (item.separator) {
          return <div key={i} style={{ height: 1, background: 'var(--border-color)', margin: '4px 0' }} />;
        }
        return (
          <div
            key={i}
            role="menuitem"
            tabIndex={0}
            onClick={() => {
              if (!item.disabled) {
                item.action();
                onClose();
              }
            }}
            onKeyDown={e => {
              if (e.key === 'Enter' && !item.disabled) {
                item.action();
                onClose();
              }
            }}
            style={{
              padding: '6px 12px',
              fontSize: 12,
              cursor: item.disabled ? 'default' : 'pointer',
              color: item.disabled ? 'var(--text-muted)' : 'var(--text-primary)',
              transition: 'background 100ms',
            }}
            onMouseEnter={e => {
              if (!item.disabled) (e.target as HTMLElement).style.background = 'var(--bg-hover)';
            }}
            onMouseLeave={e => {
              (e.target as HTMLElement).style.background = 'transparent';
            }}
          >
            {item.label}
          </div>
        );
      })}
    </div>
  );
}
