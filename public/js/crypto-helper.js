/**
 * VaultDrop Crypto Helper
 * Browser-side Web Crypto API (AES-GCM 256-bit)
 * Zero-Knowledge: Keys are generated and stored exclusively client-side.
 */

const VaultCrypto = {
  /**
   * Generates a new 256-bit AES-GCM cryptographic key
   * @returns {Promise<CryptoKey>}
   */
  async generateKey() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true, // extractable so we can put it in the URL hash
      ['encrypt', 'decrypt']
    );
  },

  /**
   * Exports a CryptoKey to a URL-safe Hexadecimal string
   * @param {CryptoKey} key
   * @returns {Promise<string>} 64-character hex string
   */
  async exportKeyToHex(key) {
    const raw = await window.crypto.subtle.exportKey('raw', key);
    return this.bufferToHex(raw);
  },

  /**
   * Imports a raw 256-bit key from a Hexadecimal or Base64 string
   * @param {string} keyStr
   * @returns {Promise<CryptoKey>}
   */
  async importKeyFromHex(keyStr) {
    if (!keyStr || typeof keyStr !== 'string') {
      throw new Error('Invalid key provided.');
    }
    const cleanKey = keyStr.trim();
    let buffer;

    // Check if 64-character hex string
    if (/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
      buffer = this.hexToBuffer(cleanKey);
    } else {
      // Fallback base64 decoding if needed
      try {
        const binStr = atob(cleanKey.replace(/-/g, '+').replace(/_/g, '/'));
        const len = binStr.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          bytes[i] = binStr.charCodeAt(i);
        }
        buffer = bytes.buffer;
      } catch (e) {
        throw new Error('Key format is not recognized. Expected 64-character hex string.');
      }
    }

    return await window.crypto.subtle.importKey(
      'raw',
      buffer,
      {
        name: 'AES-GCM'
      },
      false, // non-extractable after import
      ['decrypt']
    );
  },

  /**
   * Encrypts file ArrayBuffer using AES-GCM 256-bit with random 12-byte IV.
   * Prepend the 12-byte IV directly to the ciphertext for self-contained storage.
   * @param {ArrayBuffer} fileBuffer
   * @param {CryptoKey} key
   * @returns {Promise<Blob>}
   */
  async encryptFile(fileBuffer, key) {
    // Generate secure 12-byte initialization vector (standard for AES-GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      fileBuffer
    );

    // Combine IV (12 bytes) + Ciphertext
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return new Blob([combined], { type: 'application/octet-stream' });
  },

  /**
   * Decrypts combined IV + Ciphertext ArrayBuffer using AES-GCM
   * @param {ArrayBuffer} combinedBuffer
   * @param {CryptoKey} key
   * @returns {Promise<ArrayBuffer>} Decrypted plain file buffer
   */
  async decryptPayload(combinedBuffer, key) {
    if (combinedBuffer.byteLength < 12) {
      throw new Error('Corrupted payload: Insufficient byte length for IV.');
    }

    // Extract first 12 bytes as IV
    const iv = new Uint8Array(combinedBuffer.slice(0, 12));
    // Extract rest as ciphertext
    const ciphertext = combinedBuffer.slice(12);

    return await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      ciphertext
    );
  },

  /**
   * Convert ArrayBuffer to Hex string
   */
  bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  },

  /**
   * Convert Hex string to ArrayBuffer
   */
  hexToBuffer(hexStr) {
    const clean = hexStr.trim();
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  },

  /**
   * Human readable file size formatter
   */
  formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  },

  /**
   * Calculate human readable time difference / countdown
   */
  formatTimeRemaining(expiryIso) {
    const expiry = new Date(expiryIso).getTime();
    const now = Date.now();
    const diff = expiry - now;

    if (diff <= 0) {
      return { expired: true, text: 'Expired' };
    }

    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (days > 0) {
      const remHours = hours % 24;
      return { expired: false, text: `${days}d ${remHours}h remaining` };
    }
    if (hours > 0) {
      const remMin = minutes % 60;
      return { expired: false, text: `${hours}h ${remMin}m remaining` };
    }
    return { expired: false, text: `${minutes}m remaining` };
  },

  /**
   * Trigger safe client-side browser file download from Blob
   */
  saveBlobToFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'decrypted_file';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 150);
  }
};

window.VaultCrypto = VaultCrypto;
