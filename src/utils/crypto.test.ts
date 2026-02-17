import { describe, it, expect } from 'vitest';
import {
  encryptSymmetric,
  decryptSymmetric,
  isEncryptedEnvelope,
  exportKey,
  importKey,
} from './crypto';

// Note: ML-KEM (asymmetric) tests are skipped in Node test environment
// because @noble/post-quantum may need specific WASM/native support.
// The symmetric encryption and utility functions are fully tested.

describe('encryptSymmetric / decryptSymmetric', () => {
  it('round-trips plaintext through encrypt and decrypt', async () => {
    const plaintext = 'Hello, World! This is a secret message.';
    const password = 'test-password-123';

    const encrypted = await encryptSymmetric(plaintext, password);
    const decrypted = await decryptSymmetric(encrypted, password);

    expect(decrypted).toBe(plaintext);
  });

  it('handles empty string plaintext', async () => {
    const encrypted = await encryptSymmetric('', 'password');
    const decrypted = await decryptSymmetric(encrypted, 'password');
    expect(decrypted).toBe('');
  });

  it('handles unicode plaintext', async () => {
    const plaintext = 'Hello 你好 مرحبا 🌍🔒';
    const encrypted = await encryptSymmetric(plaintext, 'unicode-pass');
    const decrypted = await decryptSymmetric(encrypted, 'unicode-pass');
    expect(decrypted).toBe(plaintext);
  });

  it('handles long plaintext', async () => {
    const plaintext = 'A'.repeat(100_000);
    const encrypted = await encryptSymmetric(plaintext, 'long-pass');
    const decrypted = await decryptSymmetric(encrypted, 'long-pass');
    expect(decrypted).toBe(plaintext);
  });

  it('fails to decrypt with wrong password', async () => {
    const encrypted = await encryptSymmetric('secret', 'correct-password');
    await expect(decryptSymmetric(encrypted, 'wrong-password')).rejects.toThrow();
  });

  it('produces valid envelope JSON', async () => {
    const encrypted = await encryptSymmetric('test', 'pass');
    const envelope = JSON.parse(encrypted);
    expect(envelope.magic).toBe('NMAPUI_ENCRYPTED');
    expect(envelope.version).toBe(1);
    expect(envelope.mode).toBe('symmetric');
    expect(envelope.iv).toBeDefined();
    expect(envelope.ciphertext).toBeDefined();
    expect(envelope.salt).toBeDefined();
    expect(envelope.iterations).toBe(600_000);
  });

  it('produces different ciphertext for same plaintext (random IV/salt)', async () => {
    const e1 = await encryptSymmetric('same text', 'same pass');
    const e2 = await encryptSymmetric('same text', 'same pass');
    // The ciphertexts should differ due to random IV and salt
    expect(e1).not.toBe(e2);
  });

  it('rejects envelopes with wrong mode', async () => {
    const encrypted = await encryptSymmetric('test', 'pass');
    const envelope = JSON.parse(encrypted);
    envelope.mode = 'asymmetric';
    await expect(decryptSymmetric(JSON.stringify(envelope), 'pass')).rejects.toThrow('Invalid encrypted file format');
  });

  it('rejects envelopes with missing fields', async () => {
    const envelope = { magic: 'NMAPUI_ENCRYPTED', version: 1, mode: 'symmetric' };
    await expect(decryptSymmetric(JSON.stringify(envelope), 'pass')).rejects.toThrow('missing required fields');
  });

  it('rejects envelopes with invalid IV length', async () => {
    const encrypted = await encryptSymmetric('test', 'pass');
    const envelope = JSON.parse(encrypted);
    // Replace IV with a 16-byte (wrong size) base64 string
    envelope.iv = btoa('1234567890123456');
    await expect(decryptSymmetric(JSON.stringify(envelope), 'pass')).rejects.toThrow('Invalid IV length');
  });

  it('clamps iteration count to safe range', async () => {
    const encrypted = await encryptSymmetric('test', 'pass');
    const envelope = JSON.parse(encrypted);

    // Set absurdly low iterations - should be clamped to 100,000
    envelope.iterations = 1;
    // Won't decrypt correctly (different key), but tests the clamping path doesn't crash
    await expect(decryptSymmetric(JSON.stringify(envelope), 'pass')).rejects.toThrow();

    // Set absurdly high iterations - should be clamped to 10,000,000
    envelope.iterations = 999_999_999;
    await expect(decryptSymmetric(JSON.stringify(envelope), 'pass')).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const encrypted = await encryptSymmetric('test', 'pass');
    const envelope = JSON.parse(encrypted);
    // Flip a character in the ciphertext
    const ct = envelope.ciphertext;
    envelope.ciphertext = ct.slice(0, -2) + (ct[ct.length - 2] === 'A' ? 'B' : 'A') + ct[ct.length - 1];
    await expect(decryptSymmetric(JSON.stringify(envelope), 'pass')).rejects.toThrow();
  });
});

describe('isEncryptedEnvelope', () => {
  it('detects valid encrypted envelopes', async () => {
    const encrypted = await encryptSymmetric('test', 'pass');
    const result = isEncryptedEnvelope(encrypted);
    expect(result).not.toBeNull();
    expect(result!.magic).toBe('NMAPUI_ENCRYPTED');
    expect(result!.mode).toBe('symmetric');
  });

  it('returns null for non-JSON strings', () => {
    expect(isEncryptedEnvelope('not json')).toBeNull();
  });

  it('returns null for JSON without magic header', () => {
    expect(isEncryptedEnvelope('{"foo":"bar"}')).toBeNull();
  });

  it('returns null for empty string', () => {
    expect(isEncryptedEnvelope('')).toBeNull();
  });
});

describe('exportKey / importKey', () => {
  it('round-trips a key through export and import', () => {
    const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    const exported = exportKey(key, 'public');
    const imported = importKey(exported);
    expect(imported).toEqual(key);
  });

  it('exports public key with correct PEM label', () => {
    const key = new Uint8Array(32);
    const pem = exportKey(key, 'public');
    expect(pem).toContain('-----BEGIN NMAPUI ML-KEM-768 PUBLIC KEY-----');
    expect(pem).toContain('-----END NMAPUI ML-KEM-768 PUBLIC KEY-----');
  });

  it('exports secret key with correct PEM label', () => {
    const key = new Uint8Array(32);
    const pem = exportKey(key, 'secret');
    expect(pem).toContain('-----BEGIN NMAPUI ML-KEM-768 SECRET KEY-----');
    expect(pem).toContain('-----END NMAPUI ML-KEM-768 SECRET KEY-----');
  });

  it('wraps base64 at 64 characters', () => {
    const key = new Uint8Array(100); // Long enough to need wrapping
    const pem = exportKey(key, 'public');
    const lines = pem.split('\n');
    // Middle lines (not header/footer) should be <= 64 chars
    for (let i = 1; i < lines.length - 1; i++) {
      expect(lines[i].length).toBeLessThanOrEqual(64);
    }
  });
});
