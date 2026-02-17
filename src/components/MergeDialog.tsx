import React, { useState, useCallback, useRef } from 'react';
import { parseNmapOutput } from '../parser/nmapParser';
import type { AppStore } from '../store/appStore';

interface MergeDialogProps {
  store: AppStore;
  onClose: () => void;
}

export function MergeDialog({ store, onClose }: MergeDialogProps) {
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mergedFiles, setMergedFiles] = useState<string[]>([]);
  const [preview, setPreview] = useState<{ hosts: number; ports: number; scripts: number } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processMerge = useCallback((content: string, fileName: string) => {
    try {
      const newScan = parseNmapOutput(content);
      store.mergeScan(newScan);
      setMergedFiles(prev => [...prev, fileName]);
      setPreview({
        hosts: newScan.hosts.length,
        ports: newScan.hosts.reduce((s, h) => s + h.ports.length, 0),
        scripts: newScan.hosts.reduce((s, h) =>
          s + h.ports.reduce((ps, p) => ps + p.scripts.length, 0) + h.hostscripts.length, 0),
      });
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to parse file');
    }
  }, [store]);

  const handleFileRead = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      processMerge(reader.result as string, file.name);
    };
    reader.onerror = () => setError('Failed to read file');
    reader.readAsText(file);
  }, [processMerge]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileRead(file);
  }, [handleFileRead]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleFileRead(file);
    e.target.value = '';
  }, [handleFileRead]);

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text');
    if (text.trim()) {
      processMerge(text, 'pasted-scan');
    }
  }, [processMerge]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 560 }}>
        <div className="modal-header">
          <span className="modal-title">Import Additional Scan Results</span>
          <button className="btn btn-sm btn-ghost btn-icon" onClick={onClose} aria-label="Close">
            {'\u2715'}
          </button>
        </div>

        <div className="modal-body">
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
            Import additional nmap scan results to merge into the current scan. New hosts, ports,
            and script results will be added. Existing data will be updated if the new scan has
            more detailed information.
          </p>

          <div
            className={`drop-area merge-drop-area ${dragOver ? 'drag-over' : ''}`}
            onDragOver={e => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onPaste={handlePaste}
            onClick={() => fileInputRef.current?.click()}
            tabIndex={0}
          >
            <div className="icon-large">{'\u2B07'}</div>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>
              Drop nmap results here
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              or click to browse, or paste nmap output
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xml,.gnmap,.nmap,.txt"
              style={{ display: 'none' }}
              onChange={handleFileInput}
            />
          </div>

          {error && (
            <div className="error-banner" style={{ marginTop: 12 }}>
              {error}
            </div>
          )}

          {mergedFiles.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="section-title" style={{ fontSize: 13 }}>Merged Files</div>
              {mergedFiles.map((f, i) => (
                <div key={i} style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 0',
                  fontSize: 12,
                  color: 'var(--green)',
                }}>
                  <span>{'\u2713'}</span>
                  <span>{f}</span>
                </div>
              ))}
              {preview && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                  Last import: {preview.hosts} host{preview.hosts !== 1 ? 's' : ''},{' '}
                  {preview.ports} port{preview.ports !== 1 ? 's' : ''},{' '}
                  {preview.scripts} script result{preview.scripts !== 1 ? 's' : ''}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-sm" onClick={onClose}>
            {mergedFiles.length > 0 ? 'Done' : 'Cancel'}
          </button>
        </div>
      </div>
    </div>
  );
}
