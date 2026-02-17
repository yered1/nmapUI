import React, { useState, useRef, useCallback } from 'react';
import type { EncryptedEnvelope } from '../utils/crypto';
import { decryptSymmetric, decryptAsymmetric, importKey } from '../utils/crypto';

interface DecryptDialogProps {
  envelope: EncryptedEnvelope;
  rawContent: string;
  onDecrypted: (plaintext: string, fileName: string) => void;
  onClose: () => void;
  fileName: string;
}

export function DecryptDialog({ envelope, rawContent, onDecrypted, onClose, fileName }: DecryptDialogProps) {
  const [password, setPassword] = useState('');
  const [secretKeyPem, setSecretKeyPem] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [decrypting, setDecrypting] = useState(false);
  const keyFileRef = useRef<HTMLInputElement>(null);

  const isSymmetric = envelope.mode === 'symmetric';

  const handleLoadSecretKey = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      if (text) setSecretKeyPem(text.trim());
    };
    reader.readAsText(file);
  }, []);

  const handleDecrypt = async () => {
    setError(null);
    setDecrypting(true);

    try {
      let plaintext: string;

      if (isSymmetric) {
        if (!password) {
          setError('Please enter the password');
          setDecrypting(false);
          return;
        }
        plaintext = await decryptSymmetric(rawContent, password);
      } else {
        if (!secretKeyPem) {
          setError('Please provide the ML-KEM-768 secret key');
          setDecrypting(false);
          return;
        }
        const secretKey = importKey(secretKeyPem);
        plaintext = await decryptAsymmetric(rawContent, secretKey);
      }

      // Strip .enc extension for the output filename
      const decryptedFileName = fileName.replace(/\.enc$/, '');
      onDecrypted(plaintext, decryptedFileName);
    } catch (err: any) {
      if (isSymmetric) {
        setError('Decryption failed. Incorrect password or corrupted file.');
      } else {
        setError('Decryption failed. Wrong secret key or corrupted file.');
      }
    } finally {
      setDecrypting(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !decrypting) {
      handleDecrypt();
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Decrypt file" style={{ maxWidth: 480 }}>
        <div className="modal-header">
          <span className="modal-title">Encrypted File</span>
          <button className="btn btn-sm btn-ghost btn-icon" onClick={onClose} aria-label="Close">{'\u2715'}</button>
        </div>
        <div className="modal-body" onKeyDown={handleKeyDown}>
          {error && (
            <div className="error-banner" role="alert" style={{ marginBottom: 12 }}>
              {error}
            </div>
          )}

          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
            This file is encrypted with <strong>{isSymmetric ? 'AES-256-GCM (password)' : 'ML-KEM-768 (public key)'}</strong>.
            {isSymmetric
              ? ' Enter the password used to encrypt it.'
              : ' Provide your ML-KEM-768 secret key to decrypt it.'}
          </div>

          {isSymmetric ? (
            <div className="form-group">
              <div className="form-label">Password</div>
              <input
                className="input"
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Enter decryption password"
                autoFocus
                autoComplete="current-password"
              />
            </div>
          ) : (
            <div className="form-group">
              <div className="form-label">Secret Key</div>
              <textarea
                className="input"
                value={secretKeyPem}
                onChange={e => setSecretKeyPem(e.target.value)}
                placeholder="Paste ML-KEM-768 secret key or load from file..."
                rows={4}
                style={{ fontFamily: 'monospace', fontSize: 11, resize: 'vertical' }}
                autoFocus
              />
              <div style={{ marginTop: 6 }}>
                <button className="btn btn-sm" onClick={() => keyFileRef.current?.click()}>
                  Load Key File
                </button>
                <input
                  ref={keyFileRef}
                  type="file"
                  accept=".pem,.key,.txt"
                  style={{ display: 'none' }}
                  onChange={handleLoadSecretKey}
                />
              </div>
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={handleDecrypt} disabled={decrypting}>
            {decrypting ? 'Decrypting...' : 'Decrypt'}
          </button>
        </div>
      </div>
    </div>
  );
}
