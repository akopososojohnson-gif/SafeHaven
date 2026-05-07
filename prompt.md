# SafeHaven: Master Build Specification

## Project Identity

**Name:** SafeHaven  
**Tagline:** Zero-knowledge secrets vault. Server cannot decrypt your data. Ever.  
**License:** AGPL-3.0 (open source, auditable)  
**Version:** 1.0.0-foundation

---

## 1. Executive Summary

SafeHaven is a Bitwarden-style password and secrets manager built from first cryptographic principles. The server stores encrypted blobs it cannot decrypt. Authentication uses zero-knowledge proofs (server never sees the password). All encryption happens client-side. This is the foundational project in a security engineering competency tier.

**Platforms:** Web (browser), CLI (Linux/Windows/macOS), Desktop (Linux AppImage, Windows .exe, macOS .dmg), Mobile (Android APK, iOS), Browser Extension (Chrome/Firefox Manifest V3)

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    CLIENT APPLICATIONS                                       │
│                                                                                              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│   │   Web App    │  │   CLI Tool   │  │   Desktop    │  │   Mobile     │  │  Browser    │ │
│   │  (React)     │  │  (Rust)      │  │  (Tauri)     │  │  (React      │  │  Extension  │ │
│   │              │  │              │  │  Linux/Win/  │  │  Native)     │  │  (Manifest  │ │
│   │              │  │              │  │  macOS       │  │  Android/iOS │  │  V3)        │ │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│          │                 │                  │                  │                  │        │
│          └─────────────────┴──────────────────┴──────────────────┴──────────────────┘        │
│                                    │                                                         │
│                         ┌──────────▼──────────┐                                              │
│                         │   Crypto Core       │                                              │
│                         │   (Rust Library)    │                                              │
│                         │   • Argon2id        │                                              │
│                         │   • AES-256-GCM     │                                              │
│                         │   • Schnorr ZKP     │                                              │
│                         │   • Secure Memory   │                                              │
│                         └──────────┬──────────┘                                              │
│                                    │                                                         │
│                         ┌──────────▼──────────┐                                              │
│                         │   Platform Bindings │                                              │
│                         │   WASM / FFI / JNI  │                                              │
│                         └──────────┬──────────┘                                              │
└────────────────────────────────────┼──────────────────────────────────────────────────────────┘
                                     │
                              TLS 1.3 + HSTS
                                     │
┌────────────────────────────────────┼──────────────────────────────────────────────────────────┐
│                                    ▼                                                         │
│                              API GATEWAY                                                     │
│                         ┌──────────────────┐                                                 │
│                         │  Caddy / Traefik │                                                 │
│                         │  • TLS 1.3 only  │                                                 │
│                         │  • Rate limiting │                                                 │
│                         │  • WAF rules     │                                                 │
│                         └────────┬─────────┘                                                 │
│                                  │                                                           │
│                         ┌────────▼─────────┐                                                 │
│                         │   Go API Server  │                                                 │
│                         │                  │                                                 │
│                         │  ┌────────────┐  │  ┌────────────┐  ┌────────────┐  ┌──────────┐ │
│                         │  │ Auth Svc   │  │  │ Vault Svc  │  │ Share Svc  │  │ HIBP Svc │ │
│                         │  │ • ZKP      │  │  │ • Blobs    │  │ • Tokens   │  │ • Proxy  │ │
│                         │  │ • Sessions │  │  │ • Sync     │  │ • Revoke   │  │ • Cache  │ │
│                         │  └────────────┘  │  └────────────┘  └────────────┘  └──────────┘ │
│                         └────────┬─────────┘                                                 │
│                                  │                                                           │
│                         ┌────────▼─────────┐                                                 │
│                         │   Data Layer     │                                                 │
│                         │                  │                                                 │
│                         │  PostgreSQL 16   │  Redis 7  │  MinIO/S3  │  HashiCorp Vault     │
│                         └──────────────────┘───────────┘────────────┘──────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Cryptographic Specification

### 3.1 Key Hierarchy

```
MASTER PASSWORD (user memorized, NEVER stored anywhere)
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  ARGON2id (Client-side ONLY)                                │
│  ─────────────────────────                                  │
│  • Algorithm: Argon2id (resistant to side-channel + GPU)    │
│  • Memory: 65536 KB (64 MB)                                 │
│  • Iterations: 3                                            │
│  • Parallelism: 4 threads                                   │
│  • Salt: 32 bytes (256-bit), random per user                │
│  • Hash length: 32 bytes                                    │
│  • Output: 256-bit Master Key (MK)                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌─────────────────┐
              │  MASTER KEY     │  ← 32 bytes, 256-bit
              │  (MK)           │    NEVER leaves client RAM
              └────────┬────────┘    Zeroized immediately after derivation
                       │
           ┌───────────┼───────────┐
           ▼           ▼           ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │Auth Key  │ │ KEK      │ │ ZKP Key  │
    │(32 bytes)│ │(32 bytes)│ │(Scalar)  │
    └────┬─────┘ └────┬─────┘ └────┬─────┘
         │            │            │
         ▼            ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │HKDF-SHA256│ │Encrypts  │ │Schnorr   │
    │derived   │ │Vault Key │ │private   │
    │login cred│ │(AES-GCM) │ │key x     │
    └──────────┘ └──────────┘ └──────────┘
```

**Key Derivation Function:**
```rust
// Pseudocode - actual implementation in Rust
fn derive_master_key(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 65536,      // 64 MB
        time_cost: 3,         // 3 iterations
        lanes: 4,             // 4 parallel threads
        hash_length: 32,
        ..Default::default()
    };
    argon2::hash_raw(password.as_bytes(), salt, &config)
        .expect("Argon2id computation failed")
}

fn derive_subkeys(master_key: &[u8; 32]) -> SubKeys {
    // HKDF-SHA256 with domain separation
    let hkdf = Hkdf::<Sha256>::new(None, master_key);

    let mut auth_key = [0u8; 32];
    hkdf.expand(b"safehaven-auth-v1", &mut auth_key).unwrap();

    let mut kek = [0u8; 32];
    hkdf.expand(b"safehaven-kek-v1", &mut kek).unwrap();

    let mut zkp_scalar = [0u8; 32];
    hkdf.expand(b"safehaven-zkp-v1", &mut zkp_scalar).unwrap();

    SubKeys { auth_key, kek, zkp_scalar }
}
```

### 3.2 Vault Key Wrapping

```
CLIENT REGISTRATION:
1. Generate random 256-bit Vault Key (VK)
2. Encrypt VK with KEK using AES-256-GCM:
   • IV: 12 bytes random (CSPRNG)
   • AAD: user_id || "vault-key-wrap-v1"
   • Ciphertext: 32 bytes
   • Auth Tag: 16 bytes
3. Send to server: [IV (12B) || Ciphertext (32B) || Tag (16B)] = 60 bytes total

SERVER STORES: opaque 60-byte blob (cannot decrypt without KEK)

CLIENT LOGIN:
1. Derive KEK from master password via Argon2id
2. Fetch vault_key_wrap from server
3. Decrypt: VK = AES-256-GCM-Decrypt(KEK, vault_key_wrap)
4. Zeroize KEK from memory immediately
5. VK now decrypts all vault items
```

### 3.3 Zero-Knowledge Proof (Schnorr Protocol)

**Parameters:**
- Group: Ristretto255 (prime-order group, no cofactor issues)
- Generator: G (standard Ristretto base point)
- Field size: q = 2^252 + 27742317777372353535851937790883648493

**Registration:**
```
Client:
  1. Map zkp_scalar (from HKDF) to field element x ∈ Z_q
  2. Compute public key: Y = x · G (elliptic curve scalar mult)
  3. Send Y to server

Server stores: Y (32 bytes), NOT x or password
```

**Authentication:**
```
Step 1 - Challenge:
  Client → Server: { email }
  Server → Client: { challenge_id, C }
  Where C = random scalar ∈ Z_q, stored in Redis with 5-min TTL

Step 2 - Proof Generation (Client):
  1. Pick random r ∈ Z_q
  2. Compute T = r · G
  3. Compute s = r + C · x (mod q)
  4. Send { challenge_id, T, s } to server

Step 3 - Verification (Server):
  1. Retrieve C from Redis by challenge_id
  2. Fetch Y from database
  3. Verify: s · G == T + C · Y
  4. If valid → issue JWT (15-min access + 7-day refresh)
  5. If invalid → increment failed_attempts, lock after 10

Security: Server verifies knowledge of x without learning x.
Transcripts are simulatable → perfect zero-knowledge.
```

### 3.4 Vault Item Encryption

```
ENCRYPTING AN ITEM (e.g., password entry):

Input: {
  "type": "password",
  "name": "GitHub",
  "value": "super_secret_123",
  "url": "github.com",
  "notes": "Personal account",
  "tags": ["dev", "personal"]
}

1. Serialize to canonical JSON (sorted keys)
2. Compress with zstd level 3 (optional, for items > 1KB)
3. Generate random 256-bit Item Key (IK)
4. Encrypt with AES-256-GCM:
   • IV: 12 bytes random
   • AAD: item_type || item_id || version || timestamp
     (prevents type confusion and replay)
   • Plaintext: compressed JSON
   • Output: ciphertext + 16-byte auth tag
5. Encrypt IK with Vault Key (VK):
   • AES-256-GCM with separate IV
   • AAD: "item-key-wrap-v1"
   • Output: encrypted_item_key (60 bytes)
6. Package for server:
   {
     "blob_id": "uuid",
     "encrypted_data": base64(ciphertext),
     "iv": base64(iv),
     "tag": base64(tag),
     "encrypted_key": base64(encrypted_item_key),
     "key_iv": base64(key_iv),
     "aad": base64(aad),
     "version": 1,
     "compression": "zstd"  // or null
   }
7. Upload to server (opaque encrypted blob)

SERVER SEES: Cannot decrypt. Only stores opaque blob.
```

### 3.5 Secure Memory Handling

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use libc::{mlock, munlock};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecureKey {
    #[zeroize(skip)]  // Don't zero the pointer, just the data
    ptr: *mut u8,
    len: usize,
}

impl SecureKey {
    fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 64).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };

        // Prevent swapping to disk
        unsafe { mlock(ptr as *const _, size); }

        // Prevent core dumps including this memory
        unsafe { libc::madvise(ptr as *mut _, size, libc::MADV_DONTDUMP); }

        SecureKey { ptr, len: size }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // zeroize runs first (from ZeroizeOnDrop)
        unsafe {
            munlock(self.ptr as *const _, self.len);
            let layout = std::alloc::Layout::from_size_align(self.len, 64).unwrap();
            std::alloc::dealloc(self.ptr, layout);
        }
    }
}
```

**Requirements:**
- All key material uses `SecureKey` wrapper
- Keys zeroized immediately after use (not at end of scope)
- `mlock` prevents swapping to disk
- `MADV_DONTDUMP` prevents inclusion in core dumps
- Stack copies minimized (use heap-allocated secure buffers)
- No `clone()` on key material (move semantics only)

### 3.6 Time-Bound Share Links

```
SHARE CREATION:
1. Client generates random 256-bit Share Key (SK)
2. Client re-encrypts item with SK (AES-256-GCM)
3. Client uploads encrypted blob to server
4. Server:
   • Generates share_id (UUID v4)
   • Sets expiry = now() + requested_duration
   • Sets max_uses = requested_uses (default: 1)
   • Computes HMAC:
     hmac = HMAC-SHA256(
       server_secret_key,
       share_id || expiry_timestamp || max_uses
     )
   • Stores in DB:
     {share_id, blob_id, expiry, max_uses, used_count: 0, hmac, revoked: false}
5. Server returns share_id
6. Client constructs URL:
   safehaven.app/share#base64(share_id || SK)

   IMPORTANT: Fragment after # is NEVER sent to server by browser.
   The Share Key (SK) never leaves the client's control.

SHARE REDEMPTION:
1. Recipient opens URL
2. Browser extracts fragment: base64(share_id || SK)
3. Client sends share_id to server (SK stays local)
4. Server validates:
   • Lookup share_id in DB
   • Compute expected_hmac = HMAC-SHA256(secret, share_id || expiry || max_uses)
   • Verify hmac == expected_hmac (constant-time comparison)
   • Verify expiry > now()
   • Verify used_count < max_uses
   • Verify revoked == false
5. If valid:
   • Atomically increment used_count
   • Return encrypted blob
6. Client decrypts blob with SK
7. Client zeroizes SK from memory

REVOKE:
• Authenticated creator calls DELETE /shares/{share_id}
• Server verifies ownership (creator_id == authenticated user)
• Sets revoked = true
• Deletes blob from object storage
• Returns 410 Gone for future requests

SECURITY PROPERTIES:
• Tokens unforgeable without server_secret_key
• Expiry enforced server-side (cannot be tampered)
• Use counting prevents unlimited sharing
• Revocation is immediate and permanent
• SK never transmitted to server
```

### 3.7 HIBP Integration (k-Anonymity)

```
CLIENT:
1. SHA-1(password) = CBFDAC6008F9CAB4083784CBD1874F76618D2A97
2. Split:
   prefix = first 5 chars = "CBFDA"
   suffix = remainder = "C6008F9CAB4083784CBD1874F76618D2A97"
3. GET /api/v1/hibp/check?prefix=CBFDA

SERVER (PROXY):
1. Check Redis cache for prefix "CBFDA"
   • Hit: return cached suffix list
   • Miss: continue
2. GET https://api.pwnedpasswords.com/range/CBFDA
   • Headers: Add-Padding: true (prevent length-based tracking)
3. Parse response:
   • Lines of "SUFFIX:COUNT"
   • Cache in Redis with 1-hour TTL
4. Return JSON array to client:
   [{"suffix": "C6008F9...", "count": 142}, ...]

CLIENT:
1. Check if suffix exists in returned list
2. If found: display "Found in 142 breaches. Change immediately."
3. If not found: display "Password not found in known breaches."

PRIVACY GUARANTEES:
• Full SHA-1 hash NEVER leaves client
• Server only sees 5-char prefix (1,048,576 possible prefixes)
• HIBP API never sees client IP (proxied through server)
• Even HIBP cannot determine which password was checked
• Padding prevents size-based correlation attacks
```

---

## 4. Platform Specifications

### 4.1 Web Application (React + TypeScript)

**Tech Stack:**
- React 18 + TypeScript 5
- Vite (build tool)
- Zustand (state management)
- React Query (server state)
- Tailwind CSS (styling)
- shadcn/ui (component library)

**Crypto Integration:**
```typescript
// WebAssembly bridge
import init, { 
  derive_master_key, 
  encrypt_vault_item, 
  decrypt_vault_item,
  generate_zkp_proof,
  verify_zkp_proof  // for testing
} from '@safehaven/crypto';

// Initialize WASM module
await init();

// Derive key from password
const salt = crypto.getRandomValues(new Uint8Array(32));
const masterKey = derive_master_key(password, salt, {
  memory: 65536,
  iterations: 3,
  parallelism: 4
});
```

**Features:**
- Master password login with Argon2id progress indicator
- Vault grid/list view with search (name_hash-based)
- Item types: password, secure note, credit card, identity, SSH key, API key
- Password generator (diceware + random)
- Share link creation with expiry picker
- HIBP breach check on password creation
- Dark/light mode
- Responsive design (mobile-first)
- Offline mode with local IndexedDB cache

**Build Output:** `dist/` (static files served by Caddy)

### 4.2 CLI Tool (Rust)

**Tech Stack:**
- Rust 1.78+
- clap (CLI argument parsing)
- tokio (async runtime)
- reqwest (HTTP client)
- rpassword (secure password input)
- keyring (OS keychain integration)
- serde + serde_json

**Commands:**
```bash
# Authentication
safehaven login                          # Interactive login
safehaven logout                         # Clear session
safehaven status                         # Show login status

# Vault operations
safehaven vault list                     # List all items
safehaven vault list --type password     # Filter by type
safehaven vault search "github"          # Search by name hash
safehaven vault get <id>                 # Show decrypted item
safehaven vault add --type password      # Interactive add
safehaven vault add --type password --json '{"name":"GitHub","value":"..."}'
safehaven vault edit <id>                # Edit item
safehaven vault delete <id>              # Soft delete
safehaven vault sync                     # Force sync with server

# Password generation
safehaven generate --length 32 --symbols # Random password
safehaven generate --words 6             # Diceware passphrase
safehaven generate --pin 6               # Numeric PIN

# Sharing
safehaven share create <item_id> --expires 24h --uses 5
safehaven share revoke <share_id>

# Security
safehaven check <password>               # HIBP breach check
safehaven export --format json --file backup.json  # Encrypted export
safehaven import --file backup.json

# Configuration
safehaven config set server https://safehaven.app
safehaven config set default_vault_timeout 300
safehaven config show
```

**Secure Storage:**
- Linux: Secret Service API (libsecret) or file at `~/.config/safehaven/session.enc`
- macOS: Keychain
- Windows: Windows Credential Manager
- Session tokens encrypted with OS-provided key

**Build Outputs:**
- Linux: `safehaven` (binary) + `safehaven.deb` + `safehaven.rpm`
- Windows: `safehaven.exe`
- macOS: `safehaven` (universal binary)

### 4.3 Desktop Application (Tauri)

**Tech Stack:**
- Tauri 2.0 (Rust backend + Web frontend)
- Same React frontend as web app
- Rust crypto core compiled natively (faster than WASM)
- OS-native window management

**Features (beyond web):**
- System tray icon with quick access
- Global hotkey (e.g., Ctrl+Shift+S) for password fill
- Auto-type into other applications
- Biometric unlock (TouchID/Windows Hello)
- Local file attachments (encrypted)
- Offline-first with background sync
- Update notifications

**Platform Builds:**

**Linux (AppImage + .deb + .rpm):**
```bash
# AppImage
# - Single executable, no installation required
# - Works on any Linux distribution
# - FUSE-based, user-mountable
# - Output: SafeHaven-1.0.0-x86_64.AppImage

# .deb (Debian/Ubuntu)
# - System package with desktop entry
# - Depends: libgtk-3-0, libwebkit2gtk-4.1-0
# - Output: safehaven_1.0.0_amd64.deb

# .rpm (Fedora/openSUSE)
# - RPM package with desktop entry
# - Output: safehaven-1.0.0-1.x86_64.rpm
```

**Windows (.exe + MSI):**
```
# Portable .exe
# - Single executable, no installer
# - Output: SafeHaven-1.0.0-x64.exe

# MSI Installer
# - System installation with shortcuts
# - Registry entries for uninstall
# - Output: SafeHaven-1.0.0-x64.msi
```

**macOS (.dmg + .app):**
```
# Universal binary (x86_64 + ARM64)
# - Signed with Apple Developer ID
# - Notarized by Apple
# - Output: SafeHaven-1.0.0-universal.dmg
```

### 4.4 Mobile Application (React Native)

**Tech Stack:**
- React Native 0.74 (New Architecture)
- Expo (managed workflow where possible)
- Rust crypto core via Native Modules (JNI for Android, Swift for iOS)
- React Navigation
- MMKV (fast local storage)
- React Native Biometrics
- React Native Keychain

**Features:**
- Biometric unlock (FaceID/TouchID/Fingerprint)
- Auto-fill service (Android Autofill Framework, iOS Password AutoFill)
- Camera for scanning QR codes (2FA setup)
- Push notifications for breach alerts
- Offline vault access
- Secure clipboard (auto-clear after 30 seconds)

**Android:**
- Minimum SDK: 26 (Android 8.0)
- Target SDK: 34 (Android 14)
- Output: `app-release.apk` + `app.aab` (Play Store)
- Permissions: Biometric, Internet, Clipboard

**iOS:**
- Minimum: iOS 15.0
- Output: `SafeHaven.ipa` (TestFlight + App Store)
- Entitlements: Keychain, Biometric, Push Notifications

### 4.5 Browser Extension (Manifest V3)

**Tech Stack:**
- TypeScript
- Webpack/Vite for bundling
- WASM crypto module (same as web app)
- Chrome Extension API / WebExtension API

**Features:**
- Auto-fill login forms on websites
- Password generator in context menu
- Detect password fields and offer generation
- Breach warning on known compromised sites
- Vault search popup
- Inline menu on password fields

**Permissions:**
- `activeTab` (for form detection)
- `storage` (local cache)
- `scripting` (content script injection)
- `host_permissions: <all_urls>` (form detection)

**Build Outputs:**
- `safehaven-extension-chrome.zip`
- `safehaven-extension-firefox.zip`

---

## 5. API Specification

### 5.1 Authentication Endpoints

```yaml
POST /api/v1/auth/register
  Request:
    Content-Type: application/json
    Body:
      email: string (validated format)
      zkp_public_key: base64 (32 bytes, Ristretto point)
      argon2_salt: base64 (32 bytes)
      argon2_memory: integer (>= 65536)
      argon2_iterations: integer (>= 3)
      argon2_parallelism: integer (>= 1)
      vault_key_wrap: base64 (60 bytes, AES-GCM encrypted)

  Response: 201 Created
    Body:
      user_id: uuid
      created_at: ISO8601

  Errors:
    409: Email already registered
    400: Invalid parameters
    422: Weak Argon2id parameters (below minimums)

POST /api/v1/auth/challenge
  Request:
    Body:
      email: string

  Response: 200 OK
    Body:
      challenge_id: uuid
      challenge: base64 (32 bytes, random scalar)
      zkp_params:
        group: "ristretto255"
        generator: base64 (standard base point)

  Rate Limit: 5 requests per IP per minute

POST /api/v1/auth/verify
  Request:
    Body:
      challenge_id: uuid
      proof_t: base64 (32 bytes, Ristretto point)
      proof_s: base64 (32 bytes, scalar)

  Response: 200 OK
    Body:
      access_token: jwt (15-minute expiry)
      refresh_token: uuid (7-day expiry)
      token_type: "Bearer"
      expires_in: 900

  Errors:
    401: Invalid proof
    403: Account locked
    410: Challenge expired

POST /api/v1/auth/refresh
  Headers:
    Authorization: Bearer <refresh_token>

  Response: 200 OK
    Body:
      access_token: jwt
      expires_in: 900

  Errors:
    401: Invalid or revoked refresh token

POST /api/v1/auth/logout
  Headers:
    Authorization: Bearer <access_token>

  Response: 204 No Content
  // Revokes refresh token, blacklists access token in Redis

POST /api/v1/auth/mfa/enable
  Headers: Authorization: Bearer <access_token>
  Request:
    Body:
      type: "totp" | "webauthn"
      // For TOTP:
      secret: base64 (encrypted TOTP secret)
      // For WebAuthn:
      credential: WebAuthn credential object

  Response: 200 OK
    // Returns backup codes (single view)
```

### 5.2 Vault Endpoints

```yaml
GET /api/v1/vault/sync
  Headers:
    Authorization: Bearer <access_token>
  Query:
    since: ISO8601 timestamp (optional)
    include_deleted: boolean (default: false)

  Response: 200 OK
    Body:
      items:
        - id: uuid
          blob_id: uuid
          item_type: string
          version: integer
          updated_at: ISO8601
          deleted: boolean
          name_hash: base64 (optional)
          parent_id: uuid (optional)
          tags: string[]
          favorite: boolean
      deleted_ids: uuid[]
      server_timestamp: ISO8601
      has_more: boolean
      next_cursor: string (if paginated)

POST /api/v1/vault/items
  Headers:
    Authorization: Bearer <access_token>
    Content-Type: application/json
  Request:
    Body:
      item_type: string (password|secure_note|credit_card|identity|ssh_key|api_key|file)
      blob: base64 (encrypted item data)
      blob_size: integer
      name_hash: base64 (HMAC of item name)
      parent_id: uuid (optional)
      tags: string[] (optional)
      favorite: boolean (default: false)

  Response: 201 Created
    Body:
      id: uuid
      blob_id: uuid
      version: 1
      created_at: ISO8601

PUT /api/v1/vault/items/{id}
  Headers: Authorization: Bearer <access_token>
  Request:
    Body:
      // Same as POST + 
      expected_version: integer (optimistic locking)
      blob: base64 (updated encrypted data)

  Response: 200 OK
    Body:
      id: uuid
      version: integer (incremented)
      updated_at: ISO8601

  Errors:
    409: Version conflict (client has stale data)

DELETE /api/v1/vault/items/{id}
  Headers: Authorization: Bearer <access_token>
  Response: 204 No Content
  // Soft delete, preserved for sync

GET /api/v1/vault/blobs/{blob_id}
  Headers: Authorization: Bearer <access_token>
  Response: 200 OK
    Content-Type: application/octet-stream
    Body: raw encrypted bytes

  Rate Limit: 100 requests per minute per user
```

### 5.3 Share Endpoints

```yaml
POST /api/v1/shares
  Headers:
    Authorization: Bearer <access_token>
    Content-Type: application/json
  Request:
    Body:
      blob: base64 (re-encrypted item with share key)
      blob_size: integer
      expiry_hours: integer (1-720, default: 24)
      max_uses: integer (1-100, default: 1)
      password_protected: boolean (default: false)
      // If password_protected:
      password_hint: string (optional, non-sensitive)

  Response: 201 Created
    Body:
      share_id: uuid
      created_at: ISO8601

GET /api/v1/shares/{share_id}
  Query:
    token: base64 (share_id only, NOT the full token with key)

  Response: 200 OK
    Body:
      blob: base64 (encrypted item)
      expiry: ISO8601
      remaining_uses: integer
      password_protected: boolean
      password_hint: string (if applicable)

  Errors:
    404: Share not found
    410: Share expired, revoked, or exhausted

DELETE /api/v1/shares/{share_id}
  Headers: Authorization: Bearer <access_token>
  Response: 204 No Content

GET /api/v1/shares
  Headers: Authorization: Bearer <access_token>
  Response: 200 OK
    Body:
      shares:
        - share_id: uuid
          item_type: string
          expiry: ISO8601
          max_uses: integer
          used_count: integer
          revoked: boolean
          created_at: ISO8601
```

### 5.4 HIBP Endpoints

```yaml
GET /api/v1/hibp/check
  Headers:
    Authorization: Bearer <access_token>
  Query:
    prefix: string (exactly 5 hex characters)

  Response: 200 OK
    Body:
      prefix: string
      suffixes:
        - suffix: string (35 hex characters)
          count: integer
      cached: boolean
      cached_at: ISO8601 (if cached)

  Rate Limit: 60 requests per minute per user
  // Proxies to HIBP API with 1-hour Redis cache
```

### 5.5 User Endpoints

```yaml
GET /api/v1/user/me
  Headers: Authorization: Bearer <access_token>
  Response: 200 OK
    Body:
      id: uuid
      email: string
      mfa_enabled: boolean
      mfa_type: string | null
      storage_used_bytes: integer
      storage_quota_bytes: integer
      created_at: ISO8601
      last_login_at: ISO8601 | null

PUT /api/v1/user/password
  Headers: Authorization: Bearer <access_token>
  Request:
    Body:
      // Requires current ZKP proof + new vault_key_wrap
      new_zkp_public_key: base64
      new_vault_key_wrap: base64
      new_argon2_salt: base64
      // Re-encrypts all items with new key (client-side)

  Response: 200 OK

DELETE /api/v1/user
  Headers: Authorization: Bearer <access_token>
  Request:
    Body:
      confirmation: string (must be "DELETE MY ACCOUNT")

  Response: 204 No Content
  // Soft delete, data purged after 30 days
```

---

## 6. Database Schema

```sql
-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────
-- USERS
-- Server NEVER stores password, master key, or vault key.
-- ─────────────────────────────────────────────────────────────
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email               VARCHAR(255) UNIQUE NOT NULL,

    -- Zero-Knowledge Proof public key (Ristretto point, 32 bytes)
    zkp_public_key      BYTEA NOT NULL,

    -- Argon2id parameters for client-side derivation
    argon2_salt         BYTEA NOT NULL CHECK (octet_length(argon2_salt) = 32),
    argon2_memory       INTEGER NOT NULL DEFAULT 65536 CHECK (argon2_memory >= 65536),
    argon2_iterations   INTEGER NOT NULL DEFAULT 3 CHECK (argon2_iterations >= 3),
    argon2_parallelism  INTEGER NOT NULL DEFAULT 4 CHECK (argon2_parallelism >= 1),

    -- Encrypted vault key (wrapped by client's KEK)
    vault_key_wrap      BYTEA NOT NULL CHECK (octet_length(vault_key_wrap) = 60),

    -- MFA
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_type            VARCHAR(20) CHECK (mfa_type IN ('totp', 'webauthn', 'backup_codes')),
    mfa_secret          BYTEA,
    mfa_backup_codes    BYTEA,
    webauthn_credential_id BYTEA,

    -- Security
    failed_login_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    last_login_ip           INET,

    -- Account
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at          TIMESTAMPTZ,

    -- Quota
    storage_used_bytes  BIGINT NOT NULL DEFAULT 0,
    storage_quota_bytes BIGINT NOT NULL DEFAULT 1073741824,

    -- Optimistic locking
    version             INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_locked ON users(locked_until) WHERE locked_until IS NOT NULL AND deleted_at IS NULL;

-- ─────────────────────────────────────────────────────────────
-- VAULT ITEMS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE vault_items (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    blob_id         UUID NOT NULL UNIQUE,
    blob_size       INTEGER NOT NULL CHECK (blob_size > 0),

    item_type       VARCHAR(50) NOT NULL CHECK (item_type IN (
        'password', 'secure_note', 'credit_card', 
        'identity', 'ssh_key', 'api_key', 'file', 'folder'
    )),

    -- HMAC of item name for client-side search
    name_hash       BYTEA,

    parent_id       UUID REFERENCES vault_items(id) ON DELETE CASCADE,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,

    version         INTEGER NOT NULL DEFAULT 1,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    favorite        BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT valid_parent CHECK (
        parent_id IS NULL OR parent_id != id
    )
);

CREATE INDEX idx_vault_items_user ON vault_items(user_id, deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_items_user_type ON vault_items(user_id, item_type) WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_items_parent ON vault_items(parent_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_vault_items_updated ON vault_items(user_id, updated_at);

-- ─────────────────────────────────────────────────────────────
-- SHARE LINKS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE share_links (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    creator_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    blob_id         UUID NOT NULL,

    expiry          TIMESTAMPTZ NOT NULL,
    max_uses        INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    used_count      INTEGER NOT NULL DEFAULT 0 CHECK (used_count <= max_uses),

    hmac            BYTEA NOT NULL CHECK (octet_length(hmac) = 32),

    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES users(id),

    password_protected  BOOLEAN NOT NULL DEFAULT FALSE,
    password_hint       VARCHAR(255),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    last_used_ip    INET
);

CREATE INDEX idx_share_links_active ON share_links(expiry, revoked, used_count, max_uses) 
    WHERE NOT revoked AND used_count < max_uses;
CREATE INDEX idx_share_links_creator ON share_links(creator_id);

-- ─────────────────────────────────────────────────────────────
-- SESSIONS
-- ─────────────────────────────────────────────────────────────
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    refresh_token_hash  BYTEA NOT NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ DEFAULT NOW(),
    last_used_ip    INET,
    user_agent      TEXT,

    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,

    device_id       VARCHAR(255),
    device_name     VARCHAR(255)
);

CREATE INDEX idx_sessions_user ON sessions(user_id, revoked) WHERE NOT revoked;
CREATE INDEX idx_sessions_expiry ON sessions(expires_at) WHERE NOT revoked;

-- ─────────────────────────────────────────────────────────────
-- AUDIT LOG (Immutable, Partitioned)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id              BIGSERIAL,
    user_id         UUID REFERENCES users(id),

    action          VARCHAR(100) NOT NULL CHECK (action IN (
        'user_registered', 'login_success', 'login_failed', 'logout',
        'mfa_enabled', 'mfa_disabled', 'mfa_verified', 'mfa_challenge_failed',
        'vault_item_created', 'vault_item_updated', 'vault_item_deleted',
        'vault_item_accessed', 'vault_sync_initiated', 'vault_sync_completed',
        'share_created', 'share_redeemed', 'share_revoked', 'share_expired',
        'password_changed', 'account_locked', 'account_unlocked',
        'export_initiated', 'import_completed', 'hibp_check',
        'device_authorized', 'device_revoked'
    )),

    ip_address      INET,
    user_agent      TEXT,
    session_id      UUID,

    success         BOOLEAN NOT NULL,
    failure_reason  VARCHAR(255),

    details         JSONB,

    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (timestamp);

-- Initial partitions
CREATE TABLE audit_log_2026_05 PARTITION OF audit_log
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_log_2026_06 PARTITION OF audit_log
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_audit_user_time ON audit_log(user_id, timestamp);
CREATE INDEX idx_audit_action_time ON audit_log(action, timestamp);
CREATE INDEX idx_audit_ip ON audit_log(ip_address, timestamp);

-- Immutable trigger
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log is immutable and cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

-- ─────────────────────────────────────────────────────────────
-- HIBP CACHE
-- ─────────────────────────────────────────────────────────────
CREATE TABLE hibp_cache (
    prefix          VARCHAR(5) PRIMARY KEY CHECK (prefix ~ '^[A-Fa-f0-9]{5}$'),
    suffixes        JSONB NOT NULL,
    cached_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_hibp_expiry ON hibp_cache(expires_at);
```

---

## 7. Security Configuration

### 7.1 TLS / HSTS (Caddy)

```caddy
{
    auto_https off
    admin off
}

safehaven.app {
    tls {
        protocols tls1.3
        curves x25519 secp384r1
    }

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://api.safehaven.app; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
        X-XSS-Protection "0"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate"
        Pragma "no-cache"
        Expires "0"
        -Server
    }

    rate_limit {
        zone safehaven {
            key {remote_host}
            events 100
            window 1m
        }
    }

    reverse_proxy localhost:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### 7.2 Cookie Security

```go
// Go server
http.SetCookie(w, &http.Cookie{
    Name:     "__Host-session",
    Value:    sessionToken,
    Path:     "/",
    // No Domain = host-only cookie
    MaxAge:   604800,  // 7 days
    Secure:   true,
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
    Partitioned: true,
})
```

### 7.3 JWT Configuration

```go
// Access token: 15 minutes
// Refresh token: 7 days, stored as hash in DB + Redis

type Claims struct {
    UserID    uuid.UUID `json:"sub"`
    SessionID uuid.UUID `json:"sid"`
    Type      string    `json:"typ"` // "access" or "refresh"
    IssuedAt  int64     `json:"iat"`
    ExpiresAt int64     `json:"exp"`
    jwt.RegisteredClaims
}

func GenerateAccessToken(userID, sessionID uuid.UUID) (string, error) {
    claims := Claims{
        UserID:    userID,
        SessionID: sessionID,
        Type:      "access",
        IssuedAt:  time.Now().Unix(),
        ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
    }
    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
        SignedString(signingKey)
}
```

---

## 8. Build & Packaging Matrix

| Platform | Format | Tooling | Output |
|----------|--------|---------|--------|
| **Web** | Static files | Vite | `dist/` |
| **CLI Linux** | Binary | Cargo | `safehaven` |
| **CLI Linux** | .deb | cargo-deb | `safehaven_1.0.0_amd64.deb` |
| **CLI Linux** | .rpm | cargo-generate-rpm | `safehaven-1.0.0-1.x86_64.rpm` |
| **CLI Windows** | .exe | Cargo | `safehaven.exe` |
| **CLI macOS** | Binary | Cargo | `safehaven` (universal) |
| **Desktop Linux** | AppImage | Tauri | `SafeHaven-1.0.0-x86_64.AppImage` |
| **Desktop Linux** | .deb | Tauri | `safehaven_1.0.0_amd64.deb` |
| **Desktop Windows** | .exe + .msi | Tauri | `SafeHaven-1.0.0-x64-setup.exe` |
| **Desktop macOS** | .dmg | Tauri | `SafeHaven-1.0.0-universal.dmg` |
| **Mobile Android** | .apk | React Native | `app-release.apk` |
| **Mobile Android** | .aab | React Native | `app-release.aab` |
| **Mobile iOS** | .ipa | React Native | `SafeHaven.ipa` |
| **Browser** | .zip (Chrome) | Webpack | `safehaven-chrome.zip` |
| **Browser** | .zip (Firefox) | Webpack | `safehaven-firefox.zip` |

### Build Scripts

```bash
#!/bin/bash
# scripts/build-all.sh

set -e

echo "=== Building SafeHaven All Platforms ==="

# 1. Crypto Core (Rust)
echo "[1/6] Building crypto core..."
cd crypto
cargo build --release
cargo test --release
cd ..

# 2. Web App
echo "[2/6] Building web app..."
cd web
npm ci
npm run build
cd ..

# 3. CLI
echo "[3/6] Building CLI tools..."
cd cli
cargo build --release
# Linux
cp target/release/safehaven ../dist/safehaven-linux-x64
# Windows (cross-compile)
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/safehaven.exe ../dist/safehaven-windows-x64.exe
# macOS (cross-compile or CI runner)
cargo build --release --target x86_64-apple-darwin
cp target/x86_64-apple-darwin/release/safehaven ../dist/safehaven-macos-x64
cd ..

# 4. Desktop (Tauri)
echo "[4/6] Building desktop apps..."
cd desktop
cargo tauri build
# Outputs in src-tauri/target/release/bundle/
cd ..

# 5. Mobile
echo "[5/6] Building mobile apps..."
cd mobile
# Android
npx react-native build-android --mode=release
# iOS (requires macOS)
npx react-native build-ios --mode=Release
cd ..

# 6. Browser Extension
echo "[6/6] Building browser extensions..."
cd extension
npm run build:chrome
npm run build:firefox
cd ..

echo "=== Build Complete ==="
echo "Outputs in dist/"
```

---

## 9. Threat Model Summary

| Threat | Attack Vector | Mitigation | Verification |
|--------|--------------|------------|--------------|
| Server compromise | Attacker gains DB access | Zero-knowledge: server has no decryption keys | Full DB dump test |
| Memory extraction | Cold boot, swap analysis | `mlock` + `zeroize` + `MADV_DONTDUMP` | Memory forensics |
| MITM | Network interception | TLS 1.3 + certificate pinning | SSL Labs A+ |
| Session hijacking | XSS, token theft | httpOnly + SameSite=Strict + short expiry | Cookie audit |
| Password brute force | Offline cracking | Argon2id 64MB + rate limiting | Hashcat benchmark |
| Share token guessing | Random token brute force | 256-bit entropy + HMAC | Birthday bound analysis |
| Timing attacks | Side-channel comparison | Constant-time comparison everywhere | dudect testing |
| Replay attacks | Reuse old ZKP proof | Single-use challenges with 5-min TTL | Protocol analysis |
| Credential stuffing | Automated login | 5 req/min + account lockout | Load test |
| TLS downgrade | Force older protocol | TLS 1.3 minimum + HSTS | TestSSL.sh |
| Insider threat | Developer access | HashiCorp Vault + audit logs | Access review |
| Data retention | Deleted data recovery | Soft delete + crypto erasure after 30d | Policy audit |

---

## 10. Implementation Order

```
WEEK 1:  Crypto Core Foundation
         └── Rust: Argon2id, AES-256-GCM, secure memory
         └── Test: NIST vectors, memory dump verification

WEEK 2:  Zero-Knowledge Proofs
         └── Rust: Schnorr over Ristretto255
         └── Test: Soundness, completeness, ZK property

WEEK 3:  Crypto Integration & WASM
         └── WASM bindings for web
         └── FFI bindings for mobile
         └── Native integration for CLI/desktop

WEEK 4:  Go API Server - Auth
         └── Challenge generation
         └── ZKP verification
         └── JWT session management
         └── Rate limiting & lockout

WEEK 5:  Go API Server - Vault
         └── Encrypted blob storage
         └── Sync protocol
         └── Versioning & conflict resolution

WEEK 6:  Go API Server - Share & HIBP
         └── Share link generation & redemption
         └── HIBP proxy with caching
         └── Revocation mechanism

WEEK 7:  Web Application
         └── React + TypeScript + WASM crypto
         └── Vault UI, search, item management
         └── Share creation UI

WEEK 8:  CLI Tool
         └── Rust CLI with clap
         └── OS keychain integration
         └── All vault commands

WEEK 9:  Desktop Application
         └── Tauri wrapper around web app
         └── System tray, global hotkey
         └── Platform builds (AppImage, .exe, .dmg)

WEEK 10: Mobile Application
         └── React Native with native crypto modules
         └── Biometric unlock
         └── Auto-fill service integration

WEEK 11: Browser Extension
         └── Manifest V3
         └── Form detection & auto-fill
         └── Context menu integration

WEEK 12: Hardening & Audit
         └── TLS 1.3 deployment
         └── Security headers
         └── Penetration testing
         └── Crypto audit simulation
         └── Documentation
```

---

## 11. Quality Gates

Before any code is considered complete, it must pass:

1. **Unit Tests:** 100% coverage on crypto paths
2. **Integration Tests:** Full auth flow, sync protocol, share lifecycle
3. **Security Tests:**
   - Fuzzing on all API endpoints
   - Memory safety (Valgrind/AddressSanitizer)
   - Timing analysis (dudect)
   - Dependency audit (`cargo audit`, `npm audit`)
4. **Performance Tests:**
   - Argon2id derivation < 2 seconds on target hardware
   - Vault sync < 5 seconds for 1000 items
   - API response < 200ms p99
5. **Cross-Platform Tests:**
   - Web: Chrome, Firefox, Safari, Edge
   - Desktop: Ubuntu 22.04, Windows 11, macOS 14
   - Mobile: Android 14, iOS 17
   - CLI: bash, zsh, PowerShell, cmd.exe

---

## 12. File Structure

```
safehaven/
├── README.md
├── SECURITY.md
├── LICENSE (AGPL-3.0)
├── docs/
│   ├── architecture.md
│   ├── crypto-spec.md
│   ├── api-spec.md
│   ├── threat-model.md
│   ├── deployment-guide.md
│   └── audit/
│       ├── crypto-audit-2026.md
│       └── penetration-test-2026.md
│
├── crypto/                          # Rust cryptographic core
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── kdf.rs                   # Argon2id
│       ├── cipher.rs                # AES-256-GCM
│       ├── memory.rs                # Secure allocation
│       ├── zkp.rs                   # Schnorr proofs
│       ├── hash.rs                  # SHA-256, HMAC
│       ├── keys.rs                  # Key hierarchy
│       ├── share.rs                 # Share encryption
│       └── wasm.rs                  # WASM bindings
│
├── web/                             # React web application
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── components/
│       │   ├── vault/
│       │   ├── auth/
│       │   ├── share/
│       │   └── layout/
│       ├── crypto/
│       │   └── wasm-bridge.ts
│       ├── store/
│       │   └── vault-store.ts
│       ├── api/
│       │   └── client.ts
│       └── styles/
│
├── cli/                             # Rust CLI tool
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── commands/
│       │   ├── auth.rs
│       │   ├── vault.rs
│       │   ├── share.rs
│       │   ├── generate.rs
│       │   └── config.rs
│       ├── crypto/
│       │   └── native.rs
│       ├── storage/
│       │   ├── keychain.rs
│       │   └── file.rs
│       └── output/
│           └── formatter.rs
│
├── desktop/                         # Tauri desktop app
│   ├── src-tauri/
│   │   ├── Cargo.toml
│   │   ├── tauri.conf.json
│   │   └── src/
│   │       └── main.rs
│   └── src/                         # Shared web app code
│
├── mobile/                          # React Native mobile app
│   ├── package.json
│   ├── android/
│   ├── ios/
│   └── src/
│       ├── App.tsx
│       ├── crypto/
│       │   ├── android/
│       │   │   └── CryptoModule.kt
│       │   └── ios/
│       │       └── CryptoModule.swift
│       └── screens/
│
├── extension/                       # Browser extension
│   ├── manifest.json
│   ├── package.json
│   └── src/
│       ├── background.ts
│       ├── content.ts
│       ├── popup/
│       └── crypto/
│           └── wasm-bridge.ts
│
├── api/                             # Go backend
│   ├── go.mod
│   ├── Dockerfile
│   └── cmd/
│       └── server/
│           ├── main.go
│           ├── handlers/
│           │   ├── auth.go
│           │   ├── vault.go
│           │   ├── share.go
│           │   ├── hibp.go
│           │   └── user.go
│           ├── middleware/
│           │   ├── auth.go
│           │   ├── rate_limit.go
│           │   ├── security_headers.go
│           │   └── logging.go
│           ├── crypto/
│           │   └── zkp_verify.go
│           ├── models/
│           │   └── models.go
│           ├── db/
│           │   └── db.go
│           └── config/
│               └── config.go
│
├── infra/                           # Deployment
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.web
│   │   ├── docker-compose.yml
│   │   └── docker-compose.prod.yml
│   ├── k8s/
│   │   ├── namespace.yaml
│   │   ├── deployment-api.yaml
│   │   ├── deployment-web.yaml
│   │   ├── service.yaml
│   │   ├── ingress.yaml
│   │   ├── network-policy.yaml
│   │   └── secrets.yaml
│   ├── caddy/
│   │   └── Caddyfile
│   └── terraform/
│       └── main.tf
│
├── scripts/
│   ├── build-all.sh
│   ├── test-crypto.sh
│   ├── test-security.sh
│   └── release.sh
│
└── tests/
    ├── crypto/
    │   ├── argon2id_vectors.json
    │   ├── aes_gcm_vectors.json
    │   └── zkp_vectors.json
    ├── integration/
    │   ├── auth_test.go
    │   ├── vault_test.go
    │   └── share_test.go
    ├── security/
    │   ├── fuzz/
    │   ├── timing/
    │   └── memory/
    └── e2e/
        ├── web/
        ├── cli/
        └── mobile/
```

---

## 13. Success Criteria

SafeHaven is complete when:

- [ ] Argon2id derives key in < 2s with 64MB memory
- [ ] Server cannot decrypt vault with full database access
- [ ] ZKP authentication passes without password transmission
- [ ] Keys are zeroized from memory after use (verified with memory dump)
- [ ] Share links expire, enforce use limits, and revoke properly
- [ ] HIBP check reveals no full password hash to server or HIBP
- [ ] TLS 1.3 + HSTS + secure cookies on all endpoints
- [ ] All platforms build and pass tests (Web, CLI, Desktop, Mobile, Extension)
- [ ] Third-party crypto audit simulation documented with all threats mitigated
- [ ] AGPL-3.0 licensed, fully auditable source code

---

*This specification is the single source of truth. All implementations must conform to the cryptographic parameters, API contracts, and security requirements defined herein. No shortcuts. No compromises. Build it right.*## 9.5 Application Security Measures (Development Checklist)

These measures must be enforced during development, code review, and CI/CD. Every developer must verify each item before committing.

### 9.5.1 Input Validation & Sanitization

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 1 | **Never trust client input.** Validate ALL data server-side, even if client validated first. | Client-side validation is for UX, not security. | Code review: every handler validates input |
| 2 | **Use strict schemas.** JSON input must match defined struct exactly. Reject unknown fields. | Prevents mass assignment, prototype pollution. | `json:"..."` tags with `disallowUnknownFields` |
| 3 | **Validate email format with RFC 5322 regex.** Do not use simple `@` check. | Prevents header injection, SMTP injection. | Unit test with 50+ email variants |
| 4 | **Enforce length limits on ALL strings.** Passwords max 128 chars, names max 255, notes max 100KB. | Prevents DoS via memory exhaustion, ReDoS. | Middleware enforces `maxBodySize` |
| 5 | **Reject null bytes (`\x00`) in ALL text inputs.** | Null byte truncation attacks in C libraries, path traversal. | Sanitizer strips `\x00` before any processing |
| 6 | **Validate UUID format strictly.** Reject malformed UUIDs immediately. | Prevents SQL injection via UUID parameters, path traversal. | `uuid.Parse()` with error handling |
| 7 | **Sanitize filenames for uploads.** Strip path components, allow only `[a-zA-Z0-9._-]`.** | Path traversal (`../../../etc/passwd`). | Regex whitelist + `filepath.Base()` |
| 8 | **Validate base64 input.** Check padding, character set, decode before use. | Injection via malformed base64, buffer issues. | `base64.StdEncoding.Strict()` |
| 9 | **Rate limit per-user AND per-IP.** Per-IP prevents DDoS, per-user prevents credential stuffing. | Single-actor attacks from multiple IPs, botnets. | Redis-backed sliding window |
| 10 | **Use parameterized queries ONLY.** Never string-concatenate SQL. | SQL injection is still #1 OWASP threat. | `sqlc` or ORM with parameter binding |

### 9.5.2 Authentication & Session Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 11 | **ZKP challenge MUST be single-use.** Delete from Redis immediately after verification. | Replay attacks using old challenges. | Redis `GETDEL` or explicit delete |
| 12 | **Challenge TTL MUST be ≤ 5 minutes.** Expired challenges rejected unconditionally. | Window reduction for replay attacks. | Redis TTL + server-side check |
| 13 | **Account lockout after 10 failed attempts.** Lock for 30 minutes, exponential backoff. | Brute force against ZKP verification. | `failed_login_attempts` counter + `locked_until` |
| 14 | **JWT access tokens expire in 15 minutes.** Refresh tokens expire in 7 days. | Short window for token theft exploitation. | `exp` claim + server-side validation |
| 15 | **Refresh tokens are hashed (SHA-256) in database.** Store hash, not plaintext token. | Database breach does not expose active sessions. | `SHA-256(refresh_token)` before storage |
| 16 | **Refresh token rotation on every use.** Old token invalidated, new token issued. | Prevents refresh token replay after theft. | Atomic swap in transaction |
| 17 | **All tokens revoked on password change.** Immediate global logout. | Compromised password → all sessions dead. | `UPDATE sessions SET revoked=true WHERE user_id=?` |
| 18 | **MFA required for sensitive operations.** Password change, export, bulk delete. | Stolen session token still insufficient. | Middleware checks `mfa_verified` claim |
| 19 | **Session binding to device fingerprint.** IP + User-Agent hash stored, alert on change. | Session hijacking detection. | `last_used_ip`, `last_used_ua` comparison |
| 20 | **No "remember me" on shared devices.** Always require full auth on new device. | Kiosk/shared computer attacks. | Device authorization flow |

### 9.5.3 Cryptographic Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 21 | **Argon2id parameters MUST be ≥ minimums.** Memory < 64MB or iterations < 3 rejected. | Weak parameters enable GPU cracking. | Server-side validation on registration |
| 22 | **AES-GCM IV MUST be 12 bytes, random, NEVER reused.** Reused IV = catastrophic key recovery. | AES-GCM nonce reuse destroys confidentiality. | CSPRNG per encryption, monotonic counter backup |
| 23 | **All comparisons of secrets use constant-time functions.** `subtle.ConstantTimeCompare` or equivalent. | Timing side-channels leak secret data byte-by-byte. | grep for `==` on byte slices in crypto code |
| 24 | **HMAC keys MUST be 256-bit random, rotated quarterly.** Hardcoded or weak keys = forgery. | Predictable HMAC keys allow token forgery. | HashiCorp Vault dynamic secrets |
| 25 | **No deterministic encryption for searchable fields.** Use HMAC with user-specific key for name_hash. | Deterministic encryption leaks equality. | `HMAC-SHA256(name, user_search_key)` |
| 26 | **Randomness from CSPRNG only.** `crypto/rand` (Go), `getrandom` (Rust), `crypto.getRandomValues` (JS). | `Math.random()` is predictable, breaks all crypto. | Lint rule: ban `Math.random()` in crypto contexts |
| 27 | **Key material NEVER logged, even in debug mode.** | Logs are often less protected than databases. | Static analysis: no `fmt.Printf` with `[]byte` keys |
| 28 | **Private keys NEVER transmitted over network.** | Network interception of private keys = total compromise. | Architecture review: keys stay client-side |
| 29 | **Argon2id salt MUST be unique per user.** Same salt + same password = same key across users. | Rainbow table precomputation, user correlation. | `uuid` or `crypto/rand` for salt generation |
| 30 | **All cryptographic operations fail closed.** Exception in crypto = reject operation, never bypass. | Error handling bypasses enable downgrade attacks. | `?` operator in Rust, explicit error returns in Go |

### 9.5.4 Memory & Runtime Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 31 | **All key material wrapped in `SecureKey` struct.** `mlock` + `zeroize` + `MADV_DONTDUMP`. | Keys in swap/core dumps = offline extraction. | Valgrind/AddressSanitizer memory tests |
| 32 | **Keys zeroized immediately after use, not at scope end.** | Long-lived keys increase exposure window. | Code review: `zeroize()` called right after operation |
| 33 | **No `clone()` on key material.** Move semantics only. | Clones create copies that may not be zeroized. | Rust borrow checker + custom lint |
| 34 | **Stack copies of keys minimized.** Use heap-allocated secure buffers. | Stack may not be cleared, survives in memory longer. | Code review: no `let key = [0u8; 32]` for secrets |
| 35 | **Disable core dumps in production.** `ulimit -c 0` or `prctl(PR_SET_DUMPABLE, 0)`. | Core dumps contain full memory including keys. | Container security policy |
| 36 | **Disable swap or encrypt swap partition.** | Swap contains decrypted keys from `mlock` failures. | `swapoff -a` or LUKS-encrypted swap |
| 37 | **No secrets in environment variables.** | Environment is visible in `/proc/*/environ`, process listings. | HashiCorp Vault or files with 0600 permissions |
| 38 | **No secrets in command-line arguments.** | Visible in `ps`, process monitors, shell history. | Configuration files or stdin for secrets |
| 39 | **Clear clipboard after 30 seconds.** Passwords in clipboard are persistent attack surface. | Clipboard managers, remote desktop tools leak data. | Timer-based clipboard clear |
| 40 | **Screen capture protection on mobile.** `FLAG_SECURE` (Android), `UIApplication.shared.isIdleTimerDisabled` (iOS). | Malware screenshots, screen recording exfiltration. | Platform-specific flags |

### 9.5.5 Network & Transport Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 41 | **TLS 1.3 ONLY.** No TLS 1.2 fallback, no cipher suite negotiation. | TLS 1.2 has known weaknesses (POODLE, BEAST, downgrade). | `testssl.sh --tls1_3-only` |
| 42 | **HSTS with preload.** `max-age=31536000; includeSubDomains; preload`. | Prevents SSL stripping, downgrade attacks. | hstspreload.org submission |
| 43 | **Certificate pinning for mobile apps.** Embed expected SPKI hash, reject on mismatch. | CA compromise, rogue certificate issuance. | `TrustKit` (iOS), `NetworkSecurityConfig` (Android) |
| 44 | **No sensitive data in URL parameters.** URLs are logged in proxies, browser history, referer headers. | `referer` leakage, server access logs exposure. | POST body for all sensitive data |
| 45 | **CORS whitelist strict.** No `*`, no null origin, exact domain match only. | CSRF bypass, data exfiltration to attacker domain. | `Access-Control-Allow-Origin: https://safehaven.app` |
| 46 | **Content-Security-Policy blocks inline scripts.** `script-src 'self'` only. | XSS payload injection via inline `<script>`. | CSP evaluator, browser dev tools |
| 47 | **Secure cookie flags on ALL cookies.** `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` prefix. | Session hijacking via XSS, CSRF, MITM. | Cookie inspector, `curl -I` verification |
| 48 | **No mixed content.** All resources loaded over HTTPS. | Passive MITM content injection. | CSP `upgrade-insecure-requests` |
| 49 | **DNSSEC enabled on domain.** Prevents DNS cache poisoning. | Attacker redirects domain to malicious server. | `dig +dnssec safehaven.app` |
| 50 | **OCSP stapling enabled.** | Prevents privacy leak via OCSP requests, speeds handshake. | `openssl s_client -status` |

### 9.5.6 Storage & Data Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 51 | **Database encrypted at rest.** PostgreSQL TDE or filesystem-level LUKS. | Physical theft of storage media. | `pg_crypto` + LUKS verification |
| 52 | **Backup encryption with separate key.** Backup key != production key. | Backup compromise != production compromise. | HashiCorp Vault separate mount |
| 53 | **Soft delete with 30-day retention, then crypto-erasure.** Overwrite encrypted data key. | Accidental deletion recovery + eventual purging. | `deleted_at` + cron job + key destruction |
| 54 | **Audit logs immutable.** Append-only, partitioned, no UPDATE/DELETE permissions. | Attacker covers tracks by modifying logs. | PostgreSQL trigger + separate DB user |
| 55 | **No plaintext secrets in logs.** Sanitize all request/response bodies before logging. | Log aggregation systems are juicy targets. | Middleware strips sensitive fields |
| 56 | **Database credentials rotated automatically.** HashiCorp Vault dynamic credentials with TTL. | Static credentials in config files = breach vector. | Vault database secrets engine |
| 57 | **Object storage (S3/MinIO) with SSE-S3 or SSE-KMS.** Server-side encryption for blobs. | Storage provider compromise mitigation. | Bucket policy enforcement |
| 58 | **Separate encryption keys per user.** Vault Key is unique per user, not global. | One key compromise != all users compromised. | Per-user VK in database |
| 59 | **Versioned items retain old versions for 90 days.** Then crypto-erased. | Accidental overwrite recovery + data retention policy. | `version` field + cron cleanup |
| 60 | **Export files encrypted with user-provided passphrase.** Not the master password. | Export passphrase can be shared, master password cannot. | AES-256-GCM with Argon2id-derived key |

### 9.5.7 Dependency & Supply Chain Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 61 | **Pin ALL dependency versions.** Exact versions in `Cargo.lock`, `go.mod`, `package-lock.json`. | Supply chain attacks via compromised updates. | `cargo audit` flags unpinned deps |
| 62 | **Verify dependency checksums.** `cargo vendor` checksums, `npm ci` with lockfile. | Man-in-the-middle during package download. | CI enforces lockfile match |
| 63 | **No dependencies with known CVEs.** `cargo audit`, `npm audit`, `trivy` scan in CI. | Known vulnerabilities in transitive dependencies. | Block merge on CVE > MEDIUM |
| 64 | **Minimize dependency tree.** Prefer standard library over external crates/packages. | Smaller attack surface, easier audit. | Dependency count tracked per component |
| 65 | **No dependencies from unverified publishers.** Only well-maintained, audited libraries. | Malicious packages (typosquatting, backdoors). | `cargo crev` or manual vetting |
| 66 | **Build reproducibly.** Same source → same binary hash. | Supply chain verification, binary transparency. | `cargo build --locked`, deterministic builds |
| 67 | **Container images from distroless or official base.** No `ubuntu:latest`, no `alpine` with shell. | Container escape via shell, package manager. | `gcr.io/distroless/cc` base |
| 68 | **Sign all release binaries.** GPG or sigstore/cosign. | Binary tampering after build. | `cosign sign-blob` in CI |
| 69 | **SBOM generated for every release.** Software Bill of Materials for compliance. | Regulatory requirement, incident response. | `syft` + `spdx-json` output |
| 70 | **No build-time network access.** All dependencies vendored, air-gapped builds possible. | Build-time code injection via network. | `--offline` flag verification |

### 9.5.8 Error Handling & Information Disclosure

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 71 | **Generic error messages to client.** "Invalid credentials" not "User not found" or "Wrong password". | User enumeration, timing attacks. | All auth errors return identical message + status |
| 72 | **Detailed errors logged server-side only.** Include stack traces, internal state in logs. | Debugging without information leakage. | Structured logging with `error` level |
| 73 | **No stack traces in HTTP responses.** Even in debug mode. | Internal code structure revelation. | `recover()` middleware catches panics |
| 74 | **Consistent timing for all auth paths.** Success and failure take same time. | Timing side-channel on user existence. | Artificial delay pad to worst-case time |
| 75 | **Rate limit error responses too.** Don't reveal rate limit status differently. | Rate limit status can leak system state. | Same response format, different headers |
| 76 | **No SQL error messages to client.** | SQL structure revelation, injection confirmation. | `database error` → `internal error` mapping |
| 77 | **No file system paths in errors.** | Server directory structure revelation. | `filepath.Clean()` + generic messages |
| 78 | **Health check endpoint reveals nothing sensitive.** No version numbers, no internal IPs. | Information gathering for targeted attacks. | `/health` returns `{"status":"ok"}` only |
| 79 | **404 and 403 take same time.** | Path enumeration via timing differences. | Middleware normalizes response times |
| 80 | **No framework/version banners.** Remove `Server: nginx/1.24`, `X-Powered-By`. | Targeted exploitation of known vulnerabilities. | Header stripping in reverse proxy |

### 9.5.9 Browser Extension Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 81 | **Content script isolated from page JavaScript.** `world: "ISOLATED"` in Manifest V3. | Page scripts cannot access extension crypto. | `manifest.json` verification |
| 82 | **No `eval()` or `Function()` constructor.** CSP violation, code injection vector. | XSS via injected script execution. | ESLint `no-eval` rule |
| 83 | **Message passing validated strictly.** `chrome.runtime.sendMessage` with schema validation. | Malicious page spoofing extension messages. | Type-check all message payloads |
| 84 | **Storage encrypted with OS keychain.** Extension `storage.local` is plaintext. | Other extensions can read `storage.local`. | Native messaging to encrypt before storage |
| 85 | **Auto-fill requires user interaction.** No automatic form submission without click. | Drive-by form submission attacks. | Click event requirement |
| 86 | **Iframe detection before fill.** Don't fill passwords into invisible/hidden iframes. | Clickjacking, credential harvesting. | Visibility + origin check |
| 87 | **Domain matching strict.** Exact match or explicit wildcard, no substring match. | `github.com.attacker.com` matching `github.com`. | `===` comparison on eTLD+1 |
| 88 | **Extension update signed by Mozilla/Chrome store only.** No sideloading, no external updates. | Malicious update injection. | Store-only distribution |
| 89 | **No remote code execution.** All code bundled at build time. | Supply chain via dynamic script loading. | `script-src 'self'` CSP |
| 90 | **Content script injection limited to HTTPS only.** | HTTP pages are MITM-vulnerable. | `match: ["https://*/*"]` |

### 9.5.10 Mobile Application Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 91 | **Biometric auth required for vault unlock.** Fingerprint/FaceID, not just device PIN. | Device PIN is weaker than biometric. | `BiometricPrompt` (Android), `LocalAuthentication` (iOS) |
| 92 | **Vault data encrypted in local storage.** MMKV/SQLite encrypted with device key. | Physical device theft = data theft if unencrypted. | SQLCipher, encrypted MMKV |
| 93 | **Screenshot/screen recording blocked.** `FLAG_SECURE` (Android), `UIApplication` flag (iOS). | Malware screenshots, shoulder surfing via recording. | Platform API verification |
| 94 | **Auto-lock after app background > 5 minutes.** Re-authenticate when returning. | Device left unlocked, app resumed by attacker. | `AppState` listener + timer |
| 95 | **Clipboard cleared after 30 seconds.** Mobile clipboard is shared across apps. | Password pasted, remains in clipboard for other apps. | `Clipboard.setString('')` timer |
| 96 | **No backup of vault data to cloud.** iCloud/Google Drive backup excluded. | Cloud account compromise = vault compromise. | `android:allowBackup="false"`, iOS `NSURLIsExcludedFromBackupKey` |
| 97 | **Certificate pinning on API calls.** Embedded SPKI hash, reject on mismatch. | Rogue CA, corporate MITM proxies. | `TrustKit` / `NetworkSecurityConfig` |
| 98 | **Jailbreak/root detection.** Refuse to run on compromised devices. | Root access bypasses app sandbox, key extraction. | `rootbeer` (Android), `DTTJailbreakDetection` (iOS) |
| 99 | **Obfuscation of native crypto library.** String encryption, control flow flattening. | Reverse engineering of crypto implementation. | ProGuard/R8 rules, LLVM obfuscation |
| 100 | **Push notification payload contains NO sensitive data.** Generic alert only. | Push notifications visible on lock screen. | `{"title":"Security Alert","body":"Breach detected"}` |

### 9.5.11 Operational Security

| # | Rule | Rationale | Verification |
|---|------|-----------|------------|
| 101 | **Production secrets in HashiCorp Vault only.** No `.env` files, no hardcoded keys. | Source code leak != secret leak. | `grep -r "password\|secret\|key" --include="*.go" .` in CI |
| 102 | **Database access logging enabled.** Every query logged with user/session context. | Insider threat detection, incident forensics. | PostgreSQL `log_statement = 'all'` + pgaudit |
| 103 | **Failed login alerts to admin.** Slack/email on threshold breach. | Early detection of brute force campaigns. | SIEM rule + webhook |
| 104 | **Geographic anomaly detection.** Login from new country = alert + MFA challenge. | Account takeover from foreign IP. | MaxMind GeoIP + rule engine |
| 105 | **Regular penetration testing.** Quarterly by third-party, annual by red team. | Independent validation of security posture. | Report archive in `docs/audit/` |
| 106 | **Bug bounty program.** Public disclosure policy, safe harbor. | Crowdsourced vulnerability discovery. | `security.txt` + HackerOne/Intigriti |
| 107 | **Incident response plan documented.** 24-hour breach notification, key rotation procedure. | Regulatory compliance, customer trust. | `docs/incident-response.md` |
| 108 | **Disaster recovery tested quarterly.** Restore from backup, verify decryption works. | Backup corruption, key loss. | Scheduled DR drill |
| 109 | **Security training for all developers.** Annual OWASP Top 10, secure coding practices. | Human error is #1 cause of vulnerabilities. | Training completion tracking |
| 110 | **Code review requires security sign-off.** No merge without security reviewer approval. | Catches vulnerabilities before production. | Branch protection rule in GitHub/GitLab |

---


