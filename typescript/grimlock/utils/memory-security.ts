/**
 * Memory security utilities for Grimlock crypto module
 * 
 * Provides functions to securely erase sensitive data from memory.
 * Note: Complete memory erasure is difficult in JavaScript, but we
 * make best-effort attempts to zero out sensitive data.
 */

/**
 * Securely erase a Uint8Array by zeroing its contents
 * 
 * Note: In JavaScript, we cannot guarantee complete memory erasure
 * due to garbage collection and memory management. This function
 * makes a best-effort attempt to zero out the data.
 */
export function secureErase(data: Uint8Array): void {
  // Zero out all bytes
  data.fill(0);
  
  // In Node.js, we can try to force garbage collection hint
  // (though this is not guaranteed to work)
  if (typeof global !== 'undefined' && (global as any).gc) {
    // Only if --expose-gc flag is used
    try {
      (global as any).gc();
    } catch {
      // Ignore if gc is not available
    }
  }
}

/**
 * Securely erase multiple Uint8Arrays
 */
export function secureEraseMultiple(arrays: Uint8Array[]): void {
  for (const arr of arrays) {
    secureErase(arr);
  }
}

/**
 * Create a secure copy of data and erase the original
 * 
 * This is useful when you need to pass data but want to
 * ensure the original is zeroed.
 */
export function secureMove(data: Uint8Array): Uint8Array {
  const copy = new Uint8Array(data);
  secureErase(data);
  return copy;
}
