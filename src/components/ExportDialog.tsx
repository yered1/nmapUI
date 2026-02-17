import React, { useState, useRef, useCallback } from 'react';
import type { NmapScan, NmapHost, Note, ExportFormat, ExportOptions } from '../types/nmap';
import { exportData, getExportFilename, getExportMimeType, downloadExport } from '../utils/exportEngine';
import { exportProjectFile, downloadFile } from '../utils/storage';
import {
  type EncryptionMode,
  encryptSymmetric,
  encryptAsymmetric,
  generateKeyPair,
  exportKey,
  importKey,
} from '../utils/crypto';

interface ExportDialogProps {
  scan: NmapScan;
  hosts: NmapHost[];
  selectedIds: Set<string>;
  notes: Note[];
  rawScanData: string;
  fileName: string;
  onClose: () => void;
}

export function ExportDialog({ scan, hosts, selectedIds, notes, rawScanData, fileName, onClose }: ExportDialogProps) {
  const [format, setFormat] = useState<ExportFormat>('csv');
  const [includeHostDetails, setIncludeHostDetails] = useState(true);
  const [includePorts, setIncludePorts] = useState(true);
  const [includeScripts, setIncludeScripts] = useState(true);
  const [includeOS, setIncludeOS] = useState(true);
  const [includeTrace, setIncludeTrace] = useState(false);
  const [includeNotes, setIncludeNotes] = useState(true);
  const [exportScope, setExportScope] = useState<'all' | 'filtered' | 'selected'>(
    selectedIds.size > 0 ? 'selected' : 'filtered'
  );

  // Encryption state
  const [encryptionMode, setEncryptionMode] = useState<EncryptionMode>('none');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [publicKeyPem, setPublicKeyPem] = useState('');
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generatedKeys, setGeneratedKeys] = useState<{ publicPem: string; secretPem: string } | null>(null);
  const keyFileRef = useRef<HTMLInputElement>(null);

  const isProjectFormat = format === 'project';

  const handleLoadPublicKey = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      if (text) setPublicKeyPem(text.trim());
    };
    reader.readAsText(file);
  }, []);

  const handleGenerateKeyPair = useCallback(() => {
    const kp = generateKeyPair();
    const publicPem = exportKey(kp.publicKey, 'public');
    const secretPem = exportKey(kp.secretKey, 'secret');
    setGeneratedKeys({ publicPem, secretPem });
    setPublicKeyPem(publicPem);
  }, []);

  const handleDownloadKey = useCallback((pem: string, filename: string) => {
    downloadFile(pem, filename, 'text/plain');
  }, []);

  const handleExport = async () => {
    setError(null);

    // Validate encryption inputs
    if (isProjectFormat && encryptionMode === 'symmetric') {
      if (!password) {
        setError('Please enter a password');
        return;
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match');
        return;
      }
      if (password.length < 8) {
        setError('Password must be at least 8 characters');
        return;
      }
    }
    if (isProjectFormat && encryptionMode === 'asymmetric') {
      if (!publicKeyPem) {
        setError('Please provide an ML-KEM-768 public key');
        return;
      }
    }

    setExporting(true);

    try {
      if (isProjectFormat) {
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        const projectContent = exportProjectFile(rawScanData, fileName || scan.args || 'scan', notes);

        if (encryptionMode === 'none') {
          downloadFile(projectContent, `nmap-project-${ts}.nmapui`, 'application/json');
        } else if (encryptionMode === 'symmetric') {
          const encrypted = await encryptSymmetric(projectContent, password);
          downloadFile(encrypted, `nmap-project-${ts}.nmapui.enc`, 'application/json');
        } else if (encryptionMode === 'asymmetric') {
          const pubKey = importKey(publicKeyPem);
          const encrypted = await encryptAsymmetric(projectContent, pubKey);
          downloadFile(encrypted, `nmap-project-${ts}.nmapui.enc`, 'application/json');
        }

        onClose();
        return;
      }

      // Non-project formats
      let exportHosts = hosts;
      if (exportScope === 'selected' && selectedIds.size > 0) {
        exportHosts = hosts.filter(h => selectedIds.has(h.id));
      } else if (exportScope === 'all') {
        exportHosts = scan.hosts;
      }

      const options: ExportOptions = {
        format,
        includeHostDetails,
        includePorts,
        includeScripts,
        includeOS,
        includeTrace,
        includeNotes: includeNotes && notes.length > 0,
        notes: includeNotes ? notes : [],
      };

      const content = exportData(scan, exportHosts, options);
      const filename = getExportFilename(format);
      const mimeType = getExportMimeType(format);
      downloadExport(content, filename, mimeType);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const formats: { value: ExportFormat; label: string; desc: string }[] = [
    { value: 'project', label: 'NmapUI Project', desc: 'Portable file with scan data, notes & screenshots' },
    { value: 'csv', label: 'CSV', desc: 'Spreadsheet-compatible, one row per host/port' },
    { value: 'json', label: 'JSON', desc: 'Structured data, ideal for programmatic use' },
    { value: 'html', label: 'HTML Report', desc: 'Styled report, printable and shareable' },
    { value: 'xml', label: 'XML', desc: 'Simplified XML export' },
    { value: 'markdown', label: 'Markdown', desc: 'Documentation-friendly format' },
  ];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Export results" style={{ maxWidth: 560 }}>
        <div className="modal-header">
          <span className="modal-title">Export Results</span>
          <button className="btn btn-sm btn-ghost btn-icon" onClick={onClose} aria-label="Close export dialog">{'\u2715'}</button>
        </div>
        <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
          {error && (
            <div className="error-banner" role="alert" style={{ marginBottom: 12 }}>
              {error}
            </div>
          )}

          {/* Format */}
          <div className="form-group">
            <div className="form-label">Format</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {formats.map(f => (
                <label
                  key={f.value}
                  className="checkbox-label"
                  style={{
                    padding: '6px 10px',
                    background: format === f.value ? 'var(--accent-dim)' : 'var(--bg-tertiary)',
                    border: `1px solid ${format === f.value ? 'var(--accent-border)' : 'var(--border-color)'}`,
                    borderRadius: 'var(--radius-md)',
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="radio"
                    name="format"
                    checked={format === f.value}
                    onChange={() => setFormat(f.value)}
                    style={{ accentColor: 'var(--accent)' }}
                  />
                  <span style={{ fontWeight: 600 }}>{f.label}</span>
                  <span style={{ color: 'var(--text-muted)', marginLeft: 4, fontSize: 11 }}>&mdash; {f.desc}</span>
                </label>
              ))}
            </div>
          </div>

          {!isProjectFormat && (
            <>
              {/* Scope */}
              <div className="form-group">
                <div className="form-label">Scope</div>
                <select className="select" value={exportScope} onChange={e => setExportScope(e.target.value as 'all' | 'filtered' | 'selected')}>
                  <option value="all">All hosts ({scan.hosts.length})</option>
                  <option value="filtered">Filtered hosts ({hosts.length})</option>
                  {selectedIds.size > 0 && (
                    <option value="selected">Selected hosts ({selectedIds.size})</option>
                  )}
                </select>
              </div>

              {/* Options */}
              <div className="form-group">
                <div className="form-label">Include</div>
                <div className="export-options">
                  <label className="checkbox-label">
                    <input type="checkbox" checked={includePorts} onChange={e => setIncludePorts(e.target.checked)} />
                    Port details
                  </label>
                  <label className="checkbox-label">
                    <input type="checkbox" checked={includeOS} onChange={e => setIncludeOS(e.target.checked)} />
                    OS detection data
                  </label>
                  <label className="checkbox-label">
                    <input type="checkbox" checked={includeScripts} onChange={e => setIncludeScripts(e.target.checked)} />
                    Script output
                  </label>
                  <label className="checkbox-label">
                    <input type="checkbox" checked={includeTrace} onChange={e => setIncludeTrace(e.target.checked)} />
                    Traceroute & timing
                  </label>
                  {notes.length > 0 && (format === 'json' || format === 'html' || format === 'markdown') && (
                    <label className="checkbox-label">
                      <input type="checkbox" checked={includeNotes} onChange={e => setIncludeNotes(e.target.checked)} />
                      Notes ({notes.length})
                    </label>
                  )}
                </div>
              </div>
            </>
          )}

          {isProjectFormat && (
            <>
              <div className="form-group">
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '8px 0' }}>
                  The project file will include all scan data, {notes.length} note{notes.length !== 1 ? 's' : ''}, and all screenshots in a single portable file that can be opened on any computer with NmapUI.
                </div>
              </div>

              {/* Encryption Options */}
              <div className="form-group">
                <div className="form-label">Encryption</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label
                    className="checkbox-label"
                    style={{
                      padding: '6px 10px',
                      background: encryptionMode === 'none' ? 'var(--accent-dim)' : 'var(--bg-tertiary)',
                      border: `1px solid ${encryptionMode === 'none' ? 'var(--accent-border)' : 'var(--border-color)'}`,
                      borderRadius: 'var(--radius-md)',
                      cursor: 'pointer',
                    }}
                  >
                    <input type="radio" name="encryption" checked={encryptionMode === 'none'} onChange={() => setEncryptionMode('none')} style={{ accentColor: 'var(--accent)' }} />
                    <span style={{ fontWeight: 600 }}>No Encryption</span>
                    <span style={{ color: 'var(--text-muted)', marginLeft: 4, fontSize: 11 }}>&mdash; Plaintext project file</span>
                  </label>
                  <label
                    className="checkbox-label"
                    style={{
                      padding: '6px 10px',
                      background: encryptionMode === 'symmetric' ? 'var(--accent-dim)' : 'var(--bg-tertiary)',
                      border: `1px solid ${encryptionMode === 'symmetric' ? 'var(--accent-border)' : 'var(--border-color)'}`,
                      borderRadius: 'var(--radius-md)',
                      cursor: 'pointer',
                    }}
                  >
                    <input type="radio" name="encryption" checked={encryptionMode === 'symmetric'} onChange={() => setEncryptionMode('symmetric')} style={{ accentColor: 'var(--accent)' }} />
                    <span style={{ fontWeight: 600 }}>Password (AES-256-GCM)</span>
                    <span style={{ color: 'var(--text-muted)', marginLeft: 4, fontSize: 11 }}>&mdash; Quantum-safe symmetric encryption</span>
                  </label>
                  <label
                    className="checkbox-label"
                    style={{
                      padding: '6px 10px',
                      background: encryptionMode === 'asymmetric' ? 'var(--accent-dim)' : 'var(--bg-tertiary)',
                      border: `1px solid ${encryptionMode === 'asymmetric' ? 'var(--accent-border)' : 'var(--border-color)'}`,
                      borderRadius: 'var(--radius-md)',
                      cursor: 'pointer',
                    }}
                  >
                    <input type="radio" name="encryption" checked={encryptionMode === 'asymmetric'} onChange={() => setEncryptionMode('asymmetric')} style={{ accentColor: 'var(--accent)' }} />
                    <span style={{ fontWeight: 600 }}>Public Key (ML-KEM-768)</span>
                    <span style={{ color: 'var(--text-muted)', marginLeft: 4, fontSize: 11 }}>&mdash; Post-quantum asymmetric encryption</span>
                  </label>
                </div>
              </div>

              {/* Symmetric encryption fields */}
              {encryptionMode === 'symmetric' && (
                <div className="form-group">
                  <div className="form-label">Password</div>
                  <input
                    className="input"
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="Enter password (min 8 characters)"
                    autoComplete="new-password"
                  />
                  <input
                    className="input"
                    type="password"
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    placeholder="Confirm password"
                    autoComplete="new-password"
                    style={{ marginTop: 4 }}
                  />
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    Uses PBKDF2 (600,000 iterations) for key derivation + AES-256-GCM.
                    The recipient will need this password to open the file.
                  </div>
                </div>
              )}

              {/* Asymmetric encryption fields */}
              {encryptionMode === 'asymmetric' && (
                <div className="form-group">
                  <div className="form-label">Recipient's Public Key</div>
                  <textarea
                    className="input"
                    value={publicKeyPem}
                    onChange={e => setPublicKeyPem(e.target.value)}
                    placeholder="Paste ML-KEM-768 public key or load from file..."
                    rows={4}
                    style={{ fontFamily: 'monospace', fontSize: 11, resize: 'vertical' }}
                  />
                  <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                    <button className="btn btn-sm" onClick={() => keyFileRef.current?.click()}>
                      Load Key File
                    </button>
                    <button className="btn btn-sm" onClick={handleGenerateKeyPair}>
                      Generate Key Pair
                    </button>
                    <input
                      ref={keyFileRef}
                      type="file"
                      accept=".pem,.pub,.key,.txt"
                      style={{ display: 'none' }}
                      onChange={handleLoadPublicKey}
                    />
                  </div>

                  {generatedKeys && (
                    <div style={{ marginTop: 10, padding: 10, background: 'var(--bg-secondary)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--green)', marginBottom: 6 }}>
                        Key Pair Generated (ML-KEM-768)
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>
                        Download both keys now. The public key has been loaded for export.
                        Send the public key to anyone who should encrypt files for you.
                        Keep the secret key safe &mdash; it is required to decrypt files.
                      </div>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() => handleDownloadKey(generatedKeys.publicPem, 'nmapui-public.pem')}
                        >
                          Download Public Key
                        </button>
                        <button
                          className="btn btn-sm btn-danger"
                          onClick={() => handleDownloadKey(generatedKeys.secretPem, 'nmapui-secret.pem')}
                        >
                          Download Secret Key
                        </button>
                      </div>
                    </div>
                  )}

                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                    Uses ML-KEM-768 (FIPS 203) for quantum-safe key encapsulation + AES-256-GCM.
                    Only the holder of the corresponding secret key can decrypt the file.
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={handleExport} disabled={exporting}>
            {exporting ? 'Encrypting...' : isProjectFormat
              ? (encryptionMode !== 'none' ? 'Encrypt & Save' : 'Save Project')
              : `Export as ${format.toUpperCase()}`}
          </button>
        </div>
      </div>
    </div>
  );
}
