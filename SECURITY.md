# x4 – Security Overview

This document explains how **x4** handles encryption and decryption in the browser, which cryptographic primitives it uses, and what security properties it is *intended* to provide.

x4 is a **client-side text encryption tool** implemented in HTML, CSS and JavaScript using the browser’s **Web Crypto API**. It is designed so that:

- Encryption and decryption happen **locally in the browser**.
- The tool’s JavaScript **does not implement any logic to send plaintext or passwords to a server**.
- Users can copy ciphertext and share it over any channel (email, chat, etc.) and decrypt it later using the same passwords.

> ⚠️ x4 is a learning / practical tool, **not** a formally audited cryptographic product. It should not be used as the only protection for high-value, highly sensitive data.

---

## 1. Scope and threat model

### 1.1 Intended use

- Encrypt arbitrary text locally in the browser using user-provided passwords.
- Transfer the resulting ciphertext via any external channel (email, messaging apps, etc.).
- Decrypt the ciphertext later (or on another device) using the same tool and passwords.

### 1.2 In-scope security goals

Within the limits of a browser-based tool, x4 aims to:

- Avoid sending **plaintext** or **passwords** over the network in its own code.
- Use well-known cryptographic primitives provided by the browser’s **Web Crypto API**.
- Make password guessing harder using PBKDF2 with relatively high iteration counts and per-layer salts.
- Use **authenticated encryption** so that tampering with ciphertext is detected.

### 1.3 Explicit non-goals

x4 does **not** attempt to protect against:

- Compromise of the user’s device (malware, keyloggers, memory scrapers).
- Malicious or overly-permissive browser extensions.
- Insecure or malicious hosting environments.
- Weak or reused passwords.
- Traffic analysis or metadata leakage (who talks to whom, when, how often, etc.).
- Targeted, well-resourced attackers.

---

## 2. Cryptographic primitives

x4 uses only primitives exposed via the standard Web Crypto API (`window.crypto.subtle`):

### 2.1 Randomness

- Random values (salts, IVs/nonces) are generated using the browser’s **cryptographically secure PRNG**:
  - `window.crypto.getRandomValues(...)`.

### 2.2 Key derivation – PBKDF2

- User passwords are converted to cryptographic keys using:
  - **PBKDF2** with **HMAC** and a secure hash (SHA-256 or SHA-512 depending on configuration).
- Parameters (per key):
  - `kdf`: PBKDF2
  - `hash`: SHA-256 or SHA-512
  - `iterations`: relatively high value, chosen to be slow but usable in the browser.
  - `salt`: cryptographically random, unique per layer.
- The PBKDF2 result is used as input to generate AES-GCM keys.

### 2.3 Encryption – AES-GCM

- **Algorithm**: AES-GCM with 256-bit keys.
  - Web Crypto identifier: `{ name: "AES-GCM", length: 256 }`.
- **Mode**: Galois/Counter Mode (GCM) providing:
  - **Confidentiality** (encrypts plaintext).
  - **Integrity and authenticity** (detects tampering).
- Each encryption layer uses:
  - A unique, random IV/nonce for AES-GCM.
  - A header-bound value as **Additional Authenticated Data (AAD)** so the header is covered by the authentication tag.

---

## 3. Multi-layer encryption design

x4 applies **four AES-GCM encryption layers** to the plaintext before output:

- The user supplies **two passwords**.
- Each password is processed through PBKDF2 with its own salt and parameters to derive keys.
- These derived keys are used in sequence to encrypt the data in **four layers** (for example, alternating or otherwise combining the two password-derived key families).
- Each layer uses its **own salt** and **own IV** to avoid key/IV reuse.

High-level flow:

1. Start with the original plaintext.
2. Derive keys for layer 1…4 using PBKDF2 (with independent salts and iteration counts).
3. Apply AES-GCM layer 1 → ciphertext₁.
4. Apply AES-GCM layer 2 to ciphertext₁ → ciphertext₂.
5. Apply AES-GCM layer 3 to ciphertext₂ → ciphertext₃.
6. Apply AES-GCM layer 4 to ciphertext₃ → ciphertext₄ (final binary ciphertext).
7. Serialize salts, IVs, KDF parameters and the final ciphertext into a single structured output.

Decryption reverses this sequence (see section 5).

> Note: The **strength of the final encryption still depends heavily on password quality** and on the PBKDF2 parameters (iterations + salt).

---

## 4. Ciphertext format and serialization

x4 outputs a **text-based ciphertext** that can be copied and pasted.

### 4.1 Structure

Conceptually, the ciphertext output contains:

1. A **human-readable header** (text) that stores:
   - The fact that the data was created by x4.
   - The number of encryption layers.
   - For each layer:
     - KDF algorithm and hash (PBKDF2 with SHA-256 or SHA-512).
     - KDF iteration count.
     - KDF salt.
     - AES-GCM IV/nonce.
   - Any additional optional flags or versioning information.
2. A **base64-encoded binary blob** after the header:
   - The final AES-GCM ciphertext (output of the last layer).
   - Its associated authentication tag.

The exact formatting and delimiters are an implementation detail, but the important properties are:

- All parameters required to **re-derive keys** (salts, iterations, hash) are stored in the header.
- All parameters required to **decrypt** (IVs per layer, algorithm identifiers) are stored in the header.
- The header is bound as **AED/AAD** in AES-GCM so tampering with it fails authentication during decryption.

### 4.2 Encoding

- Binary values (salts, IVs, ciphertext, tags) are typically encoded using:
  - **Base64** or Base64url for inclusion in text form.
- The final ciphertext string is designed to be easy to copy/paste into:
  - Email body
  - Messaging apps
  - Text files

---

## 5. Encryption and decryption process

### 5.1 Encryption (high-level steps)

Given plaintext `P` and passwords `PW1` and `PW2`:

1. **Input handling**
   - Read plaintext from the “plaintext” text area.
   - Read passwords from password input fields.
   - Validate that required inputs are present.

2. **Parameter selection**
   - Decide PBKDF2 iteration counts and hash (either default or user-configured).
   - Generate random salts for each PBKDF2 derivation.
   - Generate random IVs for each AES-GCM layer.

3. **Key derivation (PBKDF2)**
   - For each layer that needs a key:
     - Convert the relevant password into a `CryptoKey` (`importKey`).
     - Run `deriveBits` or `deriveKey` with PBKDF2, passing:
       - The layer’s salt.
       - The layer’s iteration count.
       - The selected hash (SHA-256 or SHA-512).
     - Use the result to create an AES-GCM key (`importKey` with `{ name: "AES-GCM", length: 256 }`).

4. **Layered AES-GCM encryption**
   - Initialize `data = P` (encoded as UTF-8).
   - For each of the four layers:
     - Encrypt `data` with AES-GCM using the derived key and its IV, adding the header (or partial header) as AAD.
     - Set `data = ciphertext_of_this_layer` (including its auth tag).

5. **Serialize output**
   - Construct a header containing:
     - Algorithm identifiers.
     - PBKDF2 parameters (hash, iterations, salts).
     - AES-GCM IVs per layer.
     - Layer count.
   - Encode final `data` (binary ciphertext) as base64.
   - Join header + base64 ciphertext into the final text output.
   - Display final text in the “ciphertext” area.

6. **Post-encryption hygiene**
   - Clear password input fields in the UI.
   - Keep plaintext in the input area only if the user explicitly chooses to keep it (depending on UI).

### 5.2 Decryption (high-level steps)

Given ciphertext string `C` and passwords `PW1` and `PW2`:

1. **Input handling**
   - Read ciphertext from the “ciphertext” text area.
   - Parse the header and base64 payload.
   - Verify that required fields exist: algorithm, layer count, salts, IVs, etc.
   - Read passwords from password input fields.

2. **Reconstruct parameters**
   - From the header, extract for each layer:
     - PBKDF2 salt, iterations, hash.
     - AES-GCM IV.
   - Rebuild the same key derivation parameters used during encryption.

3. **Key derivation (PBKDF2)**
   - As in encryption, derive AES-GCM keys for each layer using PBKDF2 and the supplied passwords.

4. **Layered AES-GCM decryption**
   - Decode the base64 ciphertext into binary.
   - Decrypt in the **reverse order of encryption layers**:
     - Use AES-GCM with the appropriate key and IV.
     - Supply the same header as AAD.
     - If any AES-GCM operation fails (auth tag mismatch), abort with an error.
   - After the final layer, convert binary plaintext bytes back to UTF-8 text.

5. **Display plaintext**
   - Show decrypted plaintext in the “plaintext” text area.

6. **Post-decryption hygiene**
   - Clear password fields.
   - If the user copies plaintext, x4 may:
     - Show a warning about clipboard sensitivity.
     - Attempt to clear the clipboard after a short delay (best-effort only).

---

## 6. Implementation details and hardening

### 6.1 Web Worker usage

- Heavy cryptographic operations (PBKDF2 key derivations, AES-GCM) are executed in a **Web Worker** where supported.
- Benefits:
  - Keeps the UI responsive during long-running operations (high iteration counts).
  - Reduces the crypto logic running directly in the main document context.

### 6.2 Content Security Policy (CSP) compatibility

x4’s translator page is designed to work under a **strict Content Security Policy**, for example:

- Only allow scripts loaded from the same origin and from specific script files.
- Disallow inline scripts and `eval`.
- Disallow network requests from the crypto page except where explicitly needed for hosting.
- This is intended to reduce the chance that x4’s page will silently load malicious third-party JavaScript.

> Note: CSP is enforced by the hosting configuration (e.g. Netlify headers), not by x4’s JavaScript itself.

### 6.3 Clipboard handling

To reduce accidental leakage of decrypted text:

- When the user copies decrypted text, the UI can:
  - Warn that clipboard content can be accessed by other apps.
  - Attempt to overwrite the clipboard after a short timeout.

Important limitations:

- Browsers restrict clipboard APIs, and overwrite attempts are **best-effort** only.
- Once plaintext is copied to the system clipboard, other applications on the device may read it.

---

## 7. Security properties (intended) and limitations

### 7.1 Intended properties

If:

- The hosting environment serves x4 over HTTPS,
- The browser and device are not compromised,
- The CSP is configured to block untrusted scripts,
- The user chooses strong, unique passwords,

then:

- Plaintext and passwords are processed **only locally** in the browser by x4’s JavaScript and WebCrypto.
- The tool’s code does not include logic to transmit plaintext or passwords to a remote server.
- An attacker who only intercepts the ciphertext (without passwords) must:
  - Break AES-GCM-256, or
  - Successfully guess the passwords and defeat PBKDF2’s slowdown.

### 7.2 Limitations and risks

x4 does **not** protect against:

- **Weak passwords**  
  Short, guessable or reused passwords make PBKDF2 ineffective.

- **Compromised client**  
  Malware, keyloggers or malicious extensions can see plaintext and passwords before encryption.

- **Malicious hosting / injection**  
  If the hosting environment is compromised (serving modified JavaScript), x4 can be trivially subverted.

- **Metadata leakage**  
  Who you share data with, when, and via which channel is not hidden.

- **Side-channel attacks**  
  Browser-level timing or side-channel attacks are out-of-scope.

---

## 8. Recommendations for users

To use x4 more safely:

1. **Always use HTTPS**  
   Make sure the site is loaded over `https://` and that the certificate is valid.

2. **Use strong, unique passwords**  
   - Long (at least 12–16 characters).
   - Not reused from other accounts.

3. **Trust the environment**  
   - Use modern browsers.
   - Avoid running untrusted extensions.
   - Avoid using x4 on shared or public computers.

4. **Keep a secure copy of your passwords**  
   If you lose the passwords, you lose access to the plaintext. This is a normal property of strong encryption.

5. **Review the source code**  
   - x4 is intentionally simple enough to be readable.
   - Advanced users can verify that plaintext and passwords are not sent over the network in the implementation.

---

## 9. Disclaimer

x4 is provided as a **client-side utility** for learning and practical use.  
It has not undergone formal security or cryptographic audits.

Use at your own risk, and do not rely on x4 as the sole protection mechanism for data where compromise would have severe consequences.
