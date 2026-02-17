/**
 * Quantum-safe encryption utilities for NmapUI project files.
 *
 * Symmetric: AES-256-GCM with PBKDF2 key derivation (quantum-safe at 128-bit
 *            security level even against Grover's algorithm).
 *
 * Asymmetric: ML-KEM-768 (FIPS 203, NIST PQC standard) for key encapsulation,
 *             combined with AES-256-GCM for data encryption. This is quantum-safe
 *             against Shor's algorithm which breaks RSA/ECC.
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// ========== Types ==========

export type EncryptionMode = 'none' | 'symmetric' | 'asymmetric';

export interface EncryptedEnvelope {
  magic: 'NMAPUI_ENCRYPTED';
  version: 1;
  mode: EncryptionMode;
  /** Base64-encoded IV (12 bytes for AES-GCM) */
  iv: string;
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Base64-encoded PBKDF2 salt (symmetric only) */
  salt?: string;
  /** Base64-encoded ML-KEM-768 encapsulated key (asymmetric only) */
  encapsulatedKey?: string;
  /** PBKDF2 iteration count (symmetric only) */
  iterations?: number;
}

export interface MLKEMKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

// ========== Helpers ==========

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to ArrayBuffer for Web Crypto API compatibility.
 * This avoids TypeScript strict mode issues with Uint8Array vs BufferSource.
 */
function toBuffer(arr: Uint8Array): ArrayBuffer {
  // Copy to a fresh ArrayBuffer to satisfy TypeScript strict mode
  // (Uint8Array.buffer can be ArrayBufferLike which includes SharedArrayBuffer)
  const buf = new ArrayBuffer(arr.byteLength);
  new Uint8Array(buf).set(arr);
  return buf;
}

// ========== ML-KEM Key Management ==========

/**
 * Generate an ML-KEM-768 key pair for asymmetric encryption.
 * The user should save the secret key securely and can share the public key.
 */
export function generateKeyPair(): MLKEMKeyPair {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

/**
 * Export a key (public or secret) as a downloadable PEM-like text format.
 */
export function exportKey(key: Uint8Array, type: 'public' | 'secret'): string {
  const b64 = toBase64(key);
  const label = type === 'public' ? 'NMAPUI ML-KEM-768 PUBLIC KEY' : 'NMAPUI ML-KEM-768 SECRET KEY';
  // Wrap base64 at 64 characters
  const wrapped = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

/**
 * Import a key from PEM-like text format.
 */
export function importKey(pem: string): Uint8Array {
  const lines = pem.trim().split('\n');
  const b64Lines = lines.filter(l => !l.startsWith('-----'));
  const b64 = b64Lines.join('');
  return fromBase64(b64);
}

// ========== Symmetric Encryption (AES-256-GCM + PBKDF2) ==========

const PBKDF2_ITERATIONS = 600_000;

async function deriveKey(password: string, salt: Uint8Array, usage: KeyUsage[], iterations: number = PBKDF2_ITERATIONS): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toBuffer(salt),
      iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    usage
  );
}

/**
 * Encrypt plaintext with a password using AES-256-GCM + PBKDF2.
 */
export async function encryptSymmetric(plaintext: string, password: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, ['encrypt']);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    key,
    enc.encode(plaintext)
  );

  const envelope: EncryptedEnvelope = {
    magic: 'NMAPUI_ENCRYPTED',
    version: 1,
    mode: 'symmetric',
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    salt: toBase64(salt),
    iterations: PBKDF2_ITERATIONS,
  };

  return JSON.stringify(envelope);
}

/**
 * Decrypt a symmetrically encrypted envelope with a password.
 */
export async function decryptSymmetric(envelopeJson: string, password: string): Promise<string> {
  const envelope: EncryptedEnvelope = JSON.parse(envelopeJson);
  if (envelope.magic !== 'NMAPUI_ENCRYPTED' || envelope.mode !== 'symmetric') {
    throw new Error('Invalid encrypted file format');
  }
  if (!envelope.salt || !envelope.iv || !envelope.ciphertext) {
    throw new Error('Malformed envelope: missing required fields');
  }

  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  if (iv.length !== 12) {
    throw new Error('Invalid IV length');
  }
  const ciphertext = fromBase64(envelope.ciphertext);
  // Clamp iterations to a safe range to prevent DoS (too high) or weak key (too low)
  const iterations = Math.min(Math.max(envelope.iterations || PBKDF2_ITERATIONS, 100_000), 10_000_000);
  const key = await deriveKey(password, salt, ['decrypt'], iterations);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    key,
    toBuffer(ciphertext)
  );

  return new TextDecoder().decode(decrypted);
}

// ========== Asymmetric Encryption (ML-KEM-768 + AES-256-GCM) ==========

/**
 * Encrypt plaintext with an ML-KEM-768 public key.
 * Uses KEM to encapsulate a shared secret, then AES-256-GCM for bulk encryption.
 */
export async function encryptAsymmetric(plaintext: string, publicKey: Uint8Array): Promise<string> {
  const enc = new TextEncoder();

  // ML-KEM key encapsulation: generates a shared secret + ciphertext
  const { sharedSecret, cipherText: encapsulatedKey } = ml_kem768.encapsulate(publicKey);

  // Use the shared secret as AES-256-GCM key (it's already 32 bytes)
  const aesKey = await crypto.subtle.importKey(
    'raw',
    toBuffer(sharedSecret),
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    aesKey,
    enc.encode(plaintext)
  );

  const envelope: EncryptedEnvelope = {
    magic: 'NMAPUI_ENCRYPTED',
    version: 1,
    mode: 'asymmetric',
    iv: toBase64(iv),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
    encapsulatedKey: toBase64(encapsulatedKey),
  };

  return JSON.stringify(envelope);
}

/**
 * Decrypt an asymmetrically encrypted envelope with an ML-KEM-768 secret key.
 */
export async function decryptAsymmetric(envelopeJson: string, secretKey: Uint8Array): Promise<string> {
  const envelope: EncryptedEnvelope = JSON.parse(envelopeJson);
  if (envelope.magic !== 'NMAPUI_ENCRYPTED' || envelope.mode !== 'asymmetric') {
    throw new Error('Invalid encrypted file format');
  }
  if (!envelope.encapsulatedKey || !envelope.iv || !envelope.ciphertext) {
    throw new Error('Malformed envelope: missing required fields');
  }

  const encapsulatedKey = fromBase64(envelope.encapsulatedKey);
  const iv = fromBase64(envelope.iv);
  if (iv.length !== 12) {
    throw new Error('Invalid IV length');
  }
  const ciphertext = fromBase64(envelope.ciphertext);

  // ML-KEM decapsulation: recovers the shared secret
  const sharedSecret = ml_kem768.decapsulate(encapsulatedKey, secretKey);

  const aesKey = await crypto.subtle.importKey(
    'raw',
    toBuffer(sharedSecret),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toBuffer(iv) },
    aesKey,
    toBuffer(ciphertext)
  );

  return new TextDecoder().decode(decrypted);
}

// ========== Detection ==========

/**
 * Check if a string is an encrypted NmapUI envelope.
 */
export function isEncryptedEnvelope(content: string): EncryptedEnvelope | null {
  try {
    const data = JSON.parse(content);
    if (data && data.magic === 'NMAPUI_ENCRYPTED') {
      return data as EncryptedEnvelope;
    }
  } catch {
    // Not JSON or not encrypted
  }
  return null;
}
