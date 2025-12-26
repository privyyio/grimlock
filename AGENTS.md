# AI Agents Guide for Grimlock Development

This document provides guidelines for AI assistants (like Claude, GPT-4, etc.) working on the Grimlock codebase. It ensures consistent, high-quality contributions while maintaining cross-platform compatibility.

## 🎯 Project Overview

**Grimlock** is a cryptographic library with **dual implementations**:
- **Go**: `go/grimlock/`
- **TypeScript**: `typescript/grimlock/`

**Critical Requirement**: Both implementations MUST remain **100% compatible** at all times.

## 🏗️ Architecture Understanding

### Dual Implementation Pattern

```
Operation Flow:
1. User can encrypt data with Go
2. User can decrypt same data with TypeScript
3. And vice versa

Example:
Go encrypts → TypeScript decrypts ✅
TypeScript encrypts → Go decrypts ✅
```

### Version Structure

```
Current: v1 (production)
Future: v2, v3, etc.

Each version is self-contained in:
- go/grimlock/v1/
- typescript/grimlock/versions/v1/
```

## 📋 Development Rules

### Rule 1: Dual Implementation Mandate

**NEVER** implement a feature in only one language.

✅ **Correct Approach:**
```
1. Implement in Go
2. Implement in TypeScript
3. Add tests to both
4. Run cross-compatibility tests
5. Verify all tests pass
```

❌ **Incorrect Approach:**
```
1. Implement in Go
2. "TODO: Add TypeScript implementation"
```

### Rule 2: Cross-Compatibility Testing

**ALWAYS** run the cross-compatibility test suite after making changes:

```bash
cd cross-compatibility-testing
./run-tests.sh
```

**Expected Result:**
```
✅ All cross-compatibility tests passed!
Total: 4/4 test suites passing
Go → TypeScript: 7/7 tests
TypeScript → Go: 7/7 tests
```

### Rule 3: Cryptographic Consistency

Both implementations must use **identical**:
- ✅ Algorithm parameters
- ✅ Key sizes
- ✅ Nonce/IV sizes
- ✅ Context string formats
- ✅ AAD (Additional Authenticated Data)
- ✅ Serialization formats

**Example - Context String Format:**
```
✅ Correct (both use this):
context = "conversationId||messageId"

❌ Wrong (inconsistent):
Go:         "conversationId||messageId"
TypeScript: "conversationId:messageId"
```

### Rule 4: Type Safety

**Go:**
```go
// Use explicit types from types package
func EncryptPrivateKey(
    privateKey []byte,
    encryptionKey []byte,
    aad []byte,
) (*types.EncryptedPrivateKeyV1, error)
```

**TypeScript:**
```typescript
// Use explicit types from types module
export async function encryptPrivateKey(
  privateKey: Uint8Array,
  encryptionKey: Uint8Array,
  aad: Uint8Array
): Promise<EncryptedPrivateKey>
```

### Rule 5: Error Handling

**Go:**
```go
if err != nil {
    return nil, fmt.Errorf("descriptive context: %w", err)
}
```

**TypeScript:**
```typescript
if (!result) {
    throw new Error('Descriptive context: specific reason');
}
```

### Rule 6: Memory Security

**Always** erase sensitive data after use:

**Go:**
```go
defer utils.SecureErase(privateKey)
defer utils.SecureErase(sharedSecret)
```

**TypeScript:**
```typescript
// Best effort in JavaScript
privateKey.fill(0);
sharedSecret.fill(0);
```

### Rule 7: Documentation Files

**NEVER** create README files, markdown documentation files, or similar documentation unless explicitly requested by the user.

✅ **Correct Approach:**
- Only create documentation files when the user explicitly asks for them
- Focus on code implementation and inline comments instead

❌ **Incorrect Approach:**
- Creating README.md, GUIDE.md, or similar files proactively
- Creating documentation "for completeness" without being asked

## 🔧 Implementation Patterns

### Pattern 1: Adding a New Cryptographic Operation

**Step-by-Step:**

1. **Design the API** (both languages):
```go
// Go API
func NewOperation(input []byte, params types.Params) (*types.Result, error)
```

```typescript
// TypeScript API
export async function newOperation(
  input: Uint8Array,
  params: Params
): Promise<Result>
```

2. **Implement in Go** (`go/grimlock/v1/new_operation.go`):
```go
package v1

func NewOperation(input []byte, params types.Params) (*types.Result, error) {
    // Validate inputs
    if len(input) != ExpectedSize {
        return nil, fmt.Errorf("invalid input size")
    }
    
    // Perform operation
    result := performCrypto(input, params)
    
    // Return result
    return types.NewResult(result), nil
}
```

3. **Implement in TypeScript** (`typescript/grimlock/versions/v1/new-operation.ts`):
```typescript
export async function newOperation(
  input: Uint8Array,
  params: Params
): Promise<Result> {
  // Validate inputs
  if (input.length !== ExpectedSize) {
    throw new Error('Invalid input size');
  }
  
  // Perform operation
  const result = await performCrypto(input, params);
  
  // Return result
  return result;
}
```

4. **Add to main API**:
   - `go/grimlock/grimlock.go`
   - `typescript/grimlock/index.ts`

5. **Add tests**:
   - `go/grimlock/example_test.go`
   - `typescript/grimlock/test.ts`

6. **Add cross-compatibility test**:
   - Update `go-generator/main.go`
   - Update `ts-generator/generator.ts`
   - Update `go-verifier/main.go`
   - Update `ts-verifier/verifier.ts`

7. **Run all tests**:
```bash
# Go tests
cd go/grimlock && go test -v

# TypeScript tests
cd typescript/grimlock && npm test

# Cross-compatibility tests
cd cross-compatibility-testing && ./run-tests.sh
```

### Pattern 2: Fixing a Bug

**Critical**: Bugs often exist in **both** implementations!

1. **Identify the issue** in one implementation
2. **Check the other implementation** for the same issue
3. **Fix both implementations**
4. **Add regression tests** to prevent recurrence
5. **Run cross-compatibility tests**

**Example - HKDF Parameter Order Bug:**

The HKDF Expand phase had swapped parameters:

```typescript
// ❌ Bug (was calling with wrong order)
previous = await hmacSha512(prk, t);  // Wrong!

// ✅ Fix
previous = await hmacSha512(t, prk);  // Correct!
```

This bug only existed in TypeScript, but we verified Go was correct.

### Pattern 3: Updating Constants

Constants must be **identical** in both implementations:

**Go** (`v1/constants.go`):
```go
Constants = CryptoConstants{
    AESKeySize:           32,  // 256 bits
    GCMNonceSize:         12,  // 96 bits
    HKDFSaltEncryption:   "grimlock-encryption-salt",
    HKDFInfoMessageKey:   "grimlock-message-key",
}
```

**TypeScript** (`versions/v1/constants.ts`):
```typescript
export const CRYPTO_CONSTANTS_V1 = {
  aesKeySize: 32,  // 256 bits
  aesIvSize: 12,   // 96 bits (same as GCMNonceSize)
  hkdfSaltEncryption: 'grimlock-encryption-salt',
  hkdfInfoMessage: 'grimlock-message-key',
} as const;
```

**Note**: Names can differ slightly (camelCase vs PascalCase), but **values must be identical**.

## 🧪 Testing Guidelines

### Unit Tests

**Go:**
```go
func TestEncryption(t *testing.T) {
    // Arrange
    key := generateTestKey()
    plaintext := []byte("test data")
    
    // Act
    encrypted, err := Encrypt(plaintext, key)
    
    // Assert
    if err != nil {
        t.Fatalf("Encryption failed: %v", err)
    }
    
    decrypted, err := Decrypt(encrypted, key)
    if err != nil {
        t.Fatalf("Decryption failed: %v", err)
    }
    
    if !bytes.Equal(plaintext, decrypted) {
        t.Error("Decrypted text doesn't match original")
    }
}
```

**TypeScript:**
```typescript
test('encryption and decryption', async () => {
  // Arrange
  const key = generateTestKey();
  const plaintext = new TextEncoder().encode('test data');
  
  // Act
  const encrypted = await encrypt(plaintext, key);
  const decrypted = await decrypt(encrypted, key);
  
  // Assert
  expect(decrypted).toEqual(plaintext);
});
```

### Cross-Compatibility Tests

Located in `cross-compatibility-testing/`:

**Structure:**
```
1. go-generator:   Generate test data with Go
2. ts-verifier:    Verify Go data with TypeScript
3. ts-generator:   Generate test data with TypeScript
4. go-verifier:    Verify TypeScript data with Go
```

**Test Data Format:**
```json
{
  "operation": {
    "inputs": {
      "input1": "base64...",
      "input2": "base64..."
    },
    "expected": {
      "output": "base64..."
    }
  }
}
```

## 🐛 Debugging Tips

### Cross-Compatibility Failures

If tests fail, check:

1. **Algorithm Parameters** - Are they identical?
```bash
# Compare constants
diff <(grep -A5 "HKDFSalt" go/grimlock/v1/constants.go) \
     <(grep -A5 "hkdfSalt" typescript/grimlock/versions/v1/constants.ts)
```

2. **Byte Order** - Endianness issues?
```go
// Go uses big-endian for network protocols
binary.BigEndian.PutUint32(b, value)
```

3. **String Encoding** - UTF-8 everywhere?
```typescript
// TypeScript
const bytes = new TextEncoder().encode(str);  // UTF-8
```

4. **Base64 Encoding** - Standard vs URL-safe?
```go
// Go - use standard encoding
base64.StdEncoding.EncodeToString(data)
```

5. **Parameter Order** - Especially in HMAC/HKDF:
```typescript
// HMAC(key, data) vs HMAC(data, key)
// Check function signature!
function hmac(data: Uint8Array, key: Uint8Array)
```

### Debug Workflow

1. **Add temporary debug logging**:
```typescript
if (process.env.DEBUG_CRYPTO) {
  console.log('Input:', Buffer.from(input).toString('hex'));
  console.log('Output:', Buffer.from(output).toString('hex'));
}
```

2. **Run with debug flag**:
```bash
DEBUG_CRYPTO=1 npm run generate
```

3. **Compare outputs** between implementations

4. **Remove debug code** before committing

## 📝 Documentation Standards

### Code Comments

**Go:**
```go
// EncryptMessage encrypts a message payload using ephemeral key ECDH + AES-256-GCM
//
// Process:
//  1. Generate ephemeral key pair
//  2. Compute ECDH shared secret
//  3. Derive message key using HKDF
//  4. Encrypt payload with AES-256-GCM
//
// Parameters:
//   - payload: The message to encrypt
//   - userPublicKey: Recipient's public key (32 bytes)
//   - context: Message context for key derivation
//
// Returns the encrypted message or an error.
func EncryptMessage(payload types.MessagePayload, userPublicKey []byte, context types.MessageContext) (*types.EncryptedMessageV1, error)
```

**TypeScript:**
```typescript
/**
 * Encrypt a message payload using ephemeral key ECDH + AES-256-GCM
 * 
 * Process:
 * 1. Generate ephemeral key pair
 * 2. Compute ECDH shared secret
 * 3. Derive message key using HKDF
 * 4. Encrypt payload with AES-256-GCM
 * 
 * @param payload - The message to encrypt
 * @param userPublicKey - Recipient's public key (32 bytes)
 * @param context - Message context for key derivation
 * @returns The encrypted message
 */
export async function encryptMessage(
  payload: MessagePayload,
  userPublicKey: Uint8Array,
  context: MessageContext
): Promise<EncryptedMessage>
```

### README Updates

When adding features, update:
1. Main README.md (this file)
2. Language-specific READMEs
3. Cross-compatibility testing README

## 🔍 Common Pitfalls

### ❌ Pitfall 1: Assuming Same Defaults

**Issue:**
```typescript
// TypeScript defaults might differ from Go
const params = { /* uses defaults */ };
```

**Solution:**
```typescript
// Always specify explicitly
const params = {
  timeCost: 4,
  memoryCost: 131072,
  parallelism: 2
};
```

### ❌ Pitfall 2: Async/Sync Mismatch

**Issue:**
```typescript
// Go is synchronous, TypeScript async
```

**Solution:**
```typescript
// Make TypeScript async even if operation is sync
// for consistency and future-proofing
export async function operation(): Promise<Result> {
  return computeSync();  // Still return Promise
}
```

### ❌ Pitfall 3: Different Error Handling

**Issue:**
```go
// Go: errors are values
if err != nil {
    return nil, err
}
```

```typescript
// TypeScript: errors are exceptions
throw new Error('...')
```

**Solution:** Accept the idioms of each language, but ensure:
- Both signal errors for the same conditions
- Error messages are descriptive
- Errors don't leak sensitive information

### ❌ Pitfall 4: Forgetting AAD

**Issue:**
```typescript
// Forgot to pass AAD to AES-GCM
const encrypted = await gcm.encrypt(plaintext, key, iv);
```

**Solution:**
```typescript
// Always pass AAD for authenticated encryption
const aad = new TextEncoder().encode(context);
const encrypted = await gcm.encrypt(plaintext, key, iv, aad);
```

## 📚 Reference Implementation

When uncertain about implementation details, refer to:

1. **RFC Documents:**
   - RFC 5869 (HKDF)
   - RFC 7539 (ChaCha20-Poly1305) - for AEAD understanding
   - RFC 9180 (HPKE) - for hybrid encryption patterns

2. **Test Vectors:**
   - Use RFC test vectors to validate primitives
   - Cross-compatibility tests serve as integration test vectors

3. **Existing Code:**
   - Look at similar operations in the codebase
   - Follow established patterns

## 🚀 Workflow Summary

**For Every Change:**

```bash
# 1. Make changes to BOTH implementations
vim go/grimlock/v1/feature.go
vim typescript/grimlock/versions/v1/feature.ts

# 2. Run unit tests
cd go/grimlock && go test -v
cd typescript/grimlock && npm test

# 3. Run cross-compatibility tests
cd cross-compatibility-testing && ./run-tests.sh

# 4. Verify all tests pass
# ✅ All cross-compatibility tests passed!

# 5. Commit changes
git add .
git commit -m "feat: add new feature (Go + TS)"
```

## 🤖 AI Assistant Checklist

When working on Grimlock, ensure you:

- [ ] Understand this is a **dual implementation** project
- [ ] Implement features in **both Go and TypeScript**
- [ ] Maintain **100% compatibility** between implementations
- [ ] Run **cross-compatibility tests** after changes
- [ ] Follow **cryptographic best practices**
- [ ] Document **both implementations**
- [ ] Add **tests to both implementations**
- [ ] Verify **all tests pass** before completing

## 📞 Getting Help

If you encounter issues:

1. **Check cross-compatibility tests** - they often reveal the issue
2. **Compare with Go crypto libraries** - they're well-documented
3. **Review RFC specifications** - authoritative source
4. **Check existing implementations** - follow established patterns
5. **Ask for clarification** - better to ask than assume

---

**Remember**: The goal is **100% cross-platform compatibility**. Every change must work identically in both Go and TypeScript implementations.

**Success Criteria**: `./run-tests.sh` → ✅ All tests passing
