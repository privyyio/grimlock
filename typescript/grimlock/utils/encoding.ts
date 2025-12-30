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
  // Use browser-compatible approach (works in both browser and Next.js)
  // btoa is available in both browser and Node.js 18+ (which Next.js uses)
  if (typeof btoa !== 'undefined') {
    // Convert Uint8Array to binary string efficiently (handles large arrays without spread operator)
    let binary = '';
    for (let i = 0; i < data.length; i++) {
      binary += String.fromCharCode(data[i]);
    }
    return btoa(binary);
  }
  // Fallback: manual base64 encoding (shouldn't happen in modern environments)
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let result = '';
  let i = 0;
  while (i < data.length) {
    const a = data[i++];
    const b = i < data.length ? data[i++] : 0;
    const c = i < data.length ? data[i++] : 0;
    const bitmap = (a << 16) | (b << 8) | c;
    result += chars.charAt((bitmap >> 18) & 63);
    result += chars.charAt((bitmap >> 12) & 63);
    result += i - 2 < data.length ? chars.charAt((bitmap >> 6) & 63) : '=';
    result += i - 1 < data.length ? chars.charAt(bitmap & 63) : '=';
  }
  return result;
}

/**
 * Decode Base64 string to Uint8Array
 */
export function base64Decode(encoded: string): Uint8Array {
  // Use browser-compatible approach (works in both browser and Node.js with Web APIs)
  if (typeof atob !== 'undefined') {
    // Browser environment
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } else {
    // Fallback: manual base64 decoding (shouldn't happen in modern environments)
    // This is a simple base64 decoder that works without Buffer
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let bufferLength = encoded.length * 0.75;
    if (encoded[encoded.length - 1] === '=') {
      bufferLength--;
      if (encoded[encoded.length - 2] === '=') {
        bufferLength--;
      }
    }
    const bytes = new Uint8Array(bufferLength);
    let p = 0;
    for (let i = 0; i < encoded.length; i += 4) {
      const enc1 = chars.indexOf(encoded[i]);
      const enc2 = chars.indexOf(encoded[i + 1]);
      const enc3 = chars.indexOf(encoded[i + 2]);
      const enc4 = chars.indexOf(encoded[i + 3]);
      bytes[p++] = (enc1 << 2) | (enc2 >> 4);
      if (enc3 !== 64) bytes[p++] = ((enc2 << 4) & 0xf0) | (enc3 >> 2);
      if (enc4 !== 64) bytes[p++] = ((enc3 << 6) & 0xc0) | enc4;
    }
    return bytes;
  }
}

/**
 * Encode Uint8Array to hex string
 */
export function hexEncode(data: Uint8Array): string {
  // Use browser-compatible approach (works everywhere)
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decode hex string to Uint8Array
 */
export function hexDecode(encoded: string): Uint8Array {
  // Use browser-compatible approach (works everywhere)
  const bytes = new Uint8Array(encoded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(encoded.substr(i * 2, 2), 16);
  }
  return bytes;
}
