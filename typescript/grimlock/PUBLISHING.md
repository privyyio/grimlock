# Publishing Grimlock TypeScript Package to GitHub Packages

This guide explains how to publish the TypeScript Grimlock package to GitHub Packages and use it in your frontend repository.

## 📦 Publishing

### Automatic Publishing

The package is automatically published to GitHub Packages when:

1. **Tag Push**: Push a tag starting with `typescript/v` (e.g., `typescript/v1.0.0`)

   ```bash
   git tag typescript/v1.0.0
   git push origin typescript/v1.0.0
   ```

2. **Main Branch Push**: Pushes to `main` branch that modify `typescript/grimlock/` will publish a dev version

   ```bash
   git push origin main
   ```

3. **Manual Workflow**: Use GitHub Actions workflow dispatch to manually trigger a publish
   - Go to Actions → "Publish TypeScript Package to GitHub Packages"
   - Click "Run workflow"
   - Optionally specify a version

### Manual Publishing (Local)

If you need to publish manually:

```bash
cd typescript/grimlock

# Build the package
npm run build

# Publish (requires GITHUB_TOKEN in environment)
export NODE_AUTH_TOKEN=your_github_token
npm publish
```

## 🚀 Using in Your Frontend Repository

### Step 1: Configure npm to use GitHub Packages

Create or update `.npmrc` in your frontend repository root:

```ini
@privyy:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

**Important**: Replace `${GITHUB_TOKEN}` with an actual GitHub Personal Access Token (PAT) with `read:packages` permission, or use an environment variable.

### Step 2: Install the Package

```bash
npm install @privyyio/grimlock
```

Or with yarn:

```bash
yarn add @privyyio/grimlock
```

Or with pnpm:

```bash
pnpm add @privyyio/grimlock
```

### Step 3: Authenticate with GitHub Packages

You need a GitHub Personal Access Token (PAT) with `read:packages` permission:

1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate a new token with `read:packages` scope
3. Use it in one of these ways:

**Option A: Environment Variable (Recommended for CI/CD)**

```bash
export GITHUB_TOKEN=your_token_here
npm install
```

**Option B: Inline in .npmrc (Not recommended for production)**

```ini
@privyy:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_your_token_here
```

**Option C: npm login**

```bash
npm login --scope=@privyy --registry=https://npm.pkg.github.com
# Username: your_github_username
# Password: your_github_pat
# Email: your_github_email
```

### Step 4: Use in Your Code

```typescript
// Import the default export (latest version)
import grimlock from "@privyyio/grimlock";

// Or import specific versions
import { v1, getVersionManager } from "@privyyio/grimlock";

// Example: Generate a key pair
const keyPair = await grimlock.generateKeyPair();
console.log("Public Key:", keyPair.publicKey);
console.log("Private Key:", keyPair.privateKey);

// Example: Encrypt a message
const payload = {
  userMessage: "Hello!",
  assistantResponse: "Hi there!",
  context: { timestamp: Date.now() },
};

const context = {
  conversationId: "conv-123",
  messageId: "msg-456",
};

const encrypted = await grimlock.encryptMessage(
  payload,
  recipientPublicKey,
  context
);

// Example: Decrypt a message
const decrypted = await grimlock.decryptMessage(encrypted, privateKey, context);
```

### Step 5: TypeScript Configuration

If you're using TypeScript, the package includes type definitions. Make sure your `tsconfig.json` includes:

```json
{
  "compilerOptions": {
    "moduleResolution": "node",
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
```

## 🔧 CI/CD Integration

### GitHub Actions

If your frontend repo uses GitHub Actions, add this to your workflow:

```yaml
- name: Setup Node.js
  uses: actions/setup-node@v4
  with:
    node-version: "18"
    registry-url: "https://npm.pkg.github.com"
    scope: "@privyy"

- name: Install dependencies
  env:
    NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: npm ci
```

**Note**: `GITHUB_TOKEN` is automatically available in GitHub Actions and has the necessary permissions for packages in the same organization.

### Other CI/CD Platforms

For other CI/CD platforms (CircleCI, GitLab CI, etc.), set the `GITHUB_TOKEN` environment variable:

```yaml
# Example for GitLab CI
variables:
  GITHUB_TOKEN: $CI_GITHUB_TOKEN # Set in GitLab CI/CD variables

before_script:
  - echo "@privyyio:registry=https://npm.pkg.github.com" >> .npmrc
  - echo "//npm.pkg.github.com/:_authToken=$GITHUB_TOKEN" >> .npmrc
```

## 📝 Version Management

### Checking Available Versions

```bash
npm view @privyyio/grimlock versions --registry=https://npm.pkg.github.com
```

### Installing Specific Versions

```bash
npm install @privyyio/grimlock@1.0.0
```

### Updating the Package

```bash
npm update @privyy/grimlock
```

Or check for updates:

```bash
npm outdated @privyy/grimlock
```

## 🔒 Security Best Practices

1. **Never commit tokens**: Use environment variables or secrets management
2. **Use scoped tokens**: Create tokens with minimal required permissions
3. **Rotate tokens regularly**: Update tokens periodically
4. **Use CI/CD secrets**: Store tokens in your CI/CD platform's secret management

## 🐛 Troubleshooting

### Error: 401 Unauthorized

- Verify your GitHub token has `read:packages` permission
- Check that `.npmrc` is configured correctly
- Ensure the token hasn't expired

### Error: 404 Not Found

- Verify the package name is `@privyyio/grimlock`
- Check that the package has been published
- Ensure you have access to the `privyyio` organization

### Error: Cannot find module

- Run `npm install` to ensure dependencies are installed
- Check that the package is in your `package.json`
- Verify your TypeScript configuration

### Build Errors

- Ensure you're using Node.js 18 or higher
- Check that all dependencies are installed: `npm install`
- Verify TypeScript version compatibility

## 📚 Additional Resources

- [GitHub Packages Documentation](https://docs.github.com/en/packages)
- [npm Configuration](https://docs.npmjs.com/cli/v8/configuring-npm/npmrc)
- [TypeScript Module Resolution](https://www.typescriptlang.org/docs/handbook/module-resolution.html)

## 🔗 Related

- [Main README](../../README.md)
- [TypeScript README](./README.md)
- [Cross-Compatibility Testing](../../cross-compatibility-testing/README.md)
