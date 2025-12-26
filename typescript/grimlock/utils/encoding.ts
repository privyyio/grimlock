/**
 * Encoding utilities for Grimlock crypto module
 * 
 * Provides Base64 and hex encoding/decoding functions that work
 * consistently across browser and Node.js environments.
 */

/**
 * Encode Uint8Array to Base64 string
 */
export function base64Encode(data: Uint8Array): string {
  if (typeof btoa !== 'undefined') {
    // Browser environment
    const binary = String.fromCharCode(...data);
    return btoa(binary);
  } else {
    // Node.js environment
    return Buffer.from(data).toString('base64');
  }
}

/**
 * Decode Base64 string to Uint8Array
 */
export function base64Decode(encoded: string): Uint8Array {
  if (typeof atob !== 'undefined') {
    // Browser environment
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } else {
    // Node.js environment
    return new Uint8Array(Buffer.from(encoded, 'base64'));
  }
}

/**
 * Encode Uint8Array to hex string
 */
export function hexEncode(data: Uint8Array): string {
  if (typeof Buffer === 'undefined') {
    // Browser environment
    return Array.from(data)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } else {
    // Node.js environment
    return Buffer.from(data).toString('hex');
  }
}

/**
 * Decode hex string to Uint8Array
 */
export function hexDecode(encoded: string): Uint8Array {
  if (typeof Buffer === 'undefined') {
    // Browser environment
    const bytes = new Uint8Array(encoded.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(encoded.substr(i * 2, 2), 16);
    }
    return bytes;
  } else {
    // Node.js environment
    return new Uint8Array(Buffer.from(encoded, 'hex'));
  }
}
