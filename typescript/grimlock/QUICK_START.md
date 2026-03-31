# Quick Start: Using @privyy/grimlock in Your Frontend

## 🚀 Quick Setup (5 minutes)

### 1. Configure npm for GitHub Packages

Create `.npmrc` in your frontend repo root:

```ini
@privyy:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

### 2. Get a GitHub Token

1. Go to: https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select `read:packages` scope
4. Copy the token

### 3. Set the Token

**Local Development:**

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

**Or add to `.npmrc` (less secure):**

```ini
//npm.pkg.github.com/:_authToken=ghp_your_token_here
```

### 4. Install the Package

```bash
npm install @privyyio/grimlock
```

### 5. Use It!

```typescript
import grimlock from "@privyyio/grimlock";

// Generate keys
const keyPair = await grimlock.generateKeyPair();

// Encrypt
const encrypted = await grimlock.encryptMessage(payload, recipientPublicKey, {
  conversationId: "conv-123",
  messageId: "msg-456",
});

// Decrypt
const decrypted = await grimlock.decryptMessage(encrypted, privateKey, {
  conversationId: "conv-123",
  messageId: "msg-456",
});
```

## 📦 Publishing New Versions

### From Your Grimlock Repo:

**Tag-based release:**

```bash
git tag typescript/v1.0.1
git push origin typescript/v1.0.1
```

**Manual workflow:**

- Go to Actions → "Publish TypeScript Package"
- Click "Run workflow"
- Enter version (optional)

## 🔄 Updating in Frontend

```bash
npm update @privyyio/grimlock
```

Or install specific version:

```bash
npm install @privyyio/grimlock@1.0.1
```

## 📚 Full Documentation

See [PUBLISHING.md](./PUBLISHING.md) for detailed instructions.
