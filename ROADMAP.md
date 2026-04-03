# Grimlock Language Expansion Roadmap

Grimlock currently ships with **Go** and **TypeScript** implementations. This roadmap tracks the expansion to 10+ languages, ensuring each new implementation maintains 100% cross-compatibility with all existing ones.

---

## Guiding Principles

Every new language implementation must:

1. Pass the full cross-compatibility test suite against Go and TypeScript
2. Use identical cryptographic parameters (key sizes, nonces, AAD, serialization)
3. Include unit tests covering all operations
4. Provide a generator and verifier in `cross-compatibility-testing/`
5. Follow the same versioned architecture (`v1/`, `v2/`, ...)

---

## Current State

| Language | Status | Location |
|---|---|---|
| Go | ✅ Production | `go/grimlock/` |
| TypeScript | ✅ Production | `typescript/grimlock/` |

---

## Phase 1 — High-Priority Platforms (Q2 2026)

These cover the most common client environments for Privyy.io.

### Python

**Location**: `python/grimlock/`  
**Rationale**: Backend services, data pipelines, scripting, ML tooling.  
**Key Libraries**: `cryptography` (PyCA), `pyargon2`  
**Package**: `privyyio-grimlock` on PyPI

```python
from grimlock import generate_key_pair, encrypt_message, decrypt_message

key_pair = generate_key_pair()
encrypted = encrypt_message(payload, recipient_public_key, context)
decrypted = decrypt_message(encrypted, private_key, context)
```

### Rust

**Location**: `rust/grimlock/`  
**Rationale**: Systems programming, WASM compilation target, highest performance.  
**Key Libraries**: `x25519-dalek`, `aes-gcm`, `argon2`, `hkdf`  
**Package**: `grimlock` on crates.io  
**Note**: This implementation also serves as the base for the WebAssembly build.

```rust
let key_pair = grimlock::generate_key_pair()?;
let encrypted = grimlock::encrypt_message(&payload, &recipient_pub_key, &context)?;
let decrypted = grimlock::decrypt_message(&encrypted, &private_key, &context)?;
```

### Swift

**Location**: `swift/grimlock/`  
**Rationale**: Native iOS and macOS clients.  
**Key Libraries**: `CryptoKit` (Apple), `swift-crypto`  
**Package**: Swift Package Manager

```swift
let keyPair = try Grimlock.generateKeyPair()
let encrypted = try Grimlock.encryptMessage(payload, recipientPublicKey: pubKey, context: ctx)
let decrypted = try Grimlock.decryptMessage(encrypted, privateKey: privKey, context: ctx)
```

### Kotlin

**Location**: `kotlin/grimlock/`  
**Rationale**: Android and JVM-based services.  
**Key Libraries**: `Bouncy Castle`, `tink-android`  
**Package**: Maven Central / Gradle

```kotlin
val keyPair = Grimlock.generateKeyPair()
val encrypted = Grimlock.encryptMessage(payload, recipientPublicKey, context)
val decrypted = Grimlock.decryptMessage(encrypted, privateKey, context)
```

---

## Phase 2 — Enterprise & Web Platforms (Q3 2026)

### C# / .NET

**Location**: `csharp/grimlock/`  
**Rationale**: Enterprise services, Unity, Windows apps, .NET ecosystem.  
**Key Libraries**: `System.Security.Cryptography`, `Konscious.Security.Cryptography` (Argon2id)  
**Package**: NuGet

```csharp
var keyPair = await Grimlock.GenerateKeyPairAsync();
var encrypted = await Grimlock.EncryptMessageAsync(payload, recipientPublicKey, context);
var decrypted = await Grimlock.DecryptMessageAsync(encrypted, privateKey, context);
```

### Java

**Location**: `java/grimlock/`  
**Rationale**: Enterprise backends, Android (as a fallback to Kotlin).  
**Key Libraries**: `Bouncy Castle`, `tink`  
**Package**: Maven Central

```java
KeyPair keyPair = Grimlock.generateKeyPair();
EncryptedMessage encrypted = Grimlock.encryptMessage(payload, recipientPublicKey, context);
MessagePayload decrypted = Grimlock.decryptMessage(encrypted, privateKey, context);
```

### Dart / Flutter

**Location**: `dart/grimlock/`  
**Rationale**: Cross-platform mobile apps (iOS + Android) via Flutter.  
**Key Libraries**: `pointycastle`, `cryptography`  
**Package**: pub.dev

```dart
final keyPair = await Grimlock.generateKeyPair();
final encrypted = await Grimlock.encryptMessage(payload, recipientPublicKey, context);
final decrypted = await Grimlock.decryptMessage(encrypted, privateKey, context);
```

### WebAssembly (WASM)

**Location**: `wasm/grimlock/` (compiled from Rust)  
**Rationale**: Browser environments and edge runtimes (Cloudflare Workers, Deno Deploy) where the TypeScript impl cannot use native modules.  
**Toolchain**: `wasm-pack`, `wasm-bindgen`  
**Distribution**: npm package `@privyyio/grimlock-wasm`

```typescript
import init, { generate_key_pair, encrypt_message } from '@privyyio/grimlock-wasm';

await init();
const keyPair = generate_key_pair();
const encrypted = encrypt_message(payload, recipientPublicKey, context);
```

---

## Phase 3 — Additional Ecosystems (Q4 2026)

### Ruby

**Location**: `ruby/grimlock/`  
**Rationale**: Rails-based web services.  
**Key Libraries**: `rbnacl`, `openssl`  
**Package**: RubyGems

```ruby
key_pair = Grimlock.generate_key_pair
encrypted = Grimlock.encrypt_message(payload, recipient_public_key, context)
decrypted = Grimlock.decrypt_message(encrypted, private_key, context)
```

### PHP

**Location**: `php/grimlock/`  
**Rationale**: Web platforms and CMS integrations.  
**Key Libraries**: `sodium` (libsodium via ext-sodium), `paragonie/halite`  
**Package**: Packagist / Composer

```php
$keyPair = Grimlock::generateKeyPair();
$encrypted = Grimlock::encryptMessage($payload, $recipientPublicKey, $context);
$decrypted = Grimlock::decryptMessage($encrypted, $privateKey, $context);
```

### C / C++

**Location**: `c/grimlock/`  
**Rationale**: Embedded systems, IoT, and as an FFI base for languages without native crypto.  
**Key Libraries**: `libsodium`, `monocypher`  
**Distribution**: Static library + header

```c
grimlock_keypair_t kp;
grimlock_generate_key_pair(&kp);

grimlock_encrypted_message_t enc;
grimlock_encrypt_message(&payload, &kp.public_key, &context, &enc);
```

---

## Cross-Compatibility Test Matrix

Once all phases are complete, every implementation must pass bidirectional compatibility tests against every other:

| | Go | TS | Python | Rust | Swift | Kotlin | C# | Java | Dart | WASM | Ruby | PHP | C |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Go** | — | ✅ | Q2 | Q2 | Q2 | Q2 | Q3 | Q3 | Q3 | Q3 | Q4 | Q4 | Q4 |
| **TypeScript** | ✅ | — | Q2 | Q2 | Q2 | Q2 | Q3 | Q3 | Q3 | Q3 | Q4 | Q4 | Q4 |

---

## Implementation Checklist (per language)

- [ ] Core operations: `generateKeyPair`, `derivePasscodeKey`, `deriveRecoveryKey`, `encryptPrivateKey`, `decryptPrivateKey`, `encryptMessage`, `decryptMessage`, `generateRecoveryKey`
- [ ] Constants match Go/TS (`v1/constants`)
- [ ] Identical serialization format (version byte prefix, base64 encoding standard)
- [ ] Secure memory erasure (best-effort for GC languages)
- [ ] Unit tests covering all operations
- [ ] `cross-compatibility-testing/<lang>-generator/`
- [ ] `cross-compatibility-testing/<lang>-verifier/`
- [ ] `run-tests.sh` updated to include new language
- [ ] Package published to ecosystem registry
- [ ] CI/CD pipeline updated

---

## Language Count Summary

| Phase | Languages Added | Cumulative Total |
|---|---|---|
| Current | Go, TypeScript | 2 |
| Phase 1 (Q2 2026) | Python, Rust, Swift, Kotlin | 6 |
| Phase 2 (Q3 2026) | C#, Java, Dart, WebAssembly | 10 |
| Phase 3 (Q4 2026) | Ruby, PHP, C/C++ | **13** |
