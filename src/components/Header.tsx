import React from 'react';

interface HeaderProps {
  fileName: string;
  hasScan: boolean;
  onImport: () => void;
  onExport: () => void;
  onDiff: () => void;
  onMerge: () => void;
  onNewNote: () => void;
  onToggleTheme: () => void;
  theme: 'dark' | 'light';
}

export function Header({ fileName, hasScan, onImport, onExport, onDiff, onMerge, onNewNote, onToggleTheme, theme }: HeaderProps) {
  return (
    <header className="app-header" role="banner">
      <div className="app-logo">
        NmapUI <span>v1.0</span>
      </div>
      {fileName && <span className="header-filename" title={fileName}>{fileName}</span>}
      <div className="header-spacer" />
      <button
        className="btn btn-sm btn-ghost btn-icon"
        onClick={onToggleTheme}
        title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      >
        {theme === 'dark' ? '\u2600' : '\u263E'}
      </button>
      {hasScan && (
        <>
          <button className="btn btn-sm btn-ghost" onClick={onNewNote} title="New note (Ctrl+N)" aria-label="New note">
            + Note
          </button>
          <button className="btn btn-sm btn-ghost" onClick={onMerge} title="Import additional results (Ctrl+M)" aria-label="Merge scan results">
            Merge
          </button>
          <button className="btn btn-sm" onClick={onDiff} title="Compare scans (Ctrl+D)" aria-label="Compare scans">
            Compare
          </button>
          <button className="btn btn-sm" onClick={onImport} aria-label="Load new scan file">
            New Scan
          </button>
          <button className="btn btn-sm btn-primary" onClick={onExport} title="Export (Ctrl+E)" aria-label="Export results">
            Export
          </button>
        </>
      )}
    </header>
  );
}
