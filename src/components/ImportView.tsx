import React, { useState, useCallback, useRef } from 'react';

interface ImportViewProps {
  onFileLoad: (content: string, fileName: string) => void;
  error: string | null;
}

export function ImportView({ onFileLoad, error }: ImportViewProps) {
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

  const handleFile = useCallback((file: File) => {
    if (file.size > MAX_FILE_SIZE) {
      onFileLoad('', file.name);
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (content) {
        onFileLoad(content, file.name);
      }
    };
    reader.onerror = () => {
      onFileLoad('', file.name); // will trigger error in parser
    };
    reader.readAsText(file);
  }, [onFileLoad]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDragOver(false);
  }, []);

  const handleClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  }, [handleFile]);

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text');
    if (text && (text.includes('<nmaprun') || text.includes('# Nmap') || text.includes('Host:') || text.includes('Nmap scan report for') || text.includes('Starting Nmap'))) {
      onFileLoad(text, 'pasted-scan.xml');
    }
  }, [onFileLoad]);

  return (
    <div className="import-zone" onPaste={handlePaste} role="main" aria-label="Import Nmap results">
      {error && (
        <div className="error-banner" role="alert" style={{ marginBottom: 20, maxWidth: 500 }}>
          <span style={{ fontWeight: 600 }}>Error:</span> {error}
        </div>
      )}
      <div
        className={`drop-area ${dragOver ? 'drag-over' : ''}`}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={handleClick}
        role="button"
        tabIndex={0}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') handleClick(); }}
        aria-label="Drop or click to import Nmap scan file"
      >
        <div className="icon-large">{'\u2B06'}</div>
        <h2>Import Nmap Results</h2>
        <p>
          Drag & drop an Nmap output file here, click to browse,
          or paste XML content directly
        </p>
        <div className="formats">
          <span className="format-badge">XML (-oX)</span>
          <span className="format-badge">Greppable (-oG)</span>
          <span className="format-badge">Normal (-oN)</span>
          <span className="format-badge">NmapUI Project (.nmapui)</span>
          <span className="format-badge">Encrypted (.enc)</span>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".xml,.gnmap,.txt,.nmap,.nmapui,.enc"
          style={{ display: 'none' }}
          onChange={handleInputChange}
        />
      </div>
      <div style={{ marginTop: 24, color: 'var(--text-muted)', fontSize: 12, maxWidth: 500, textAlign: 'center' }}>
        Tip: Run <code className="mono" style={{ color: 'var(--accent)' }}>nmap -oX output.xml target</code> to
        generate an XML file with full scan details
      </div>
    </div>
  );
}
