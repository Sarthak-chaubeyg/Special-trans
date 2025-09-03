# X4-Translator 

![Version](https://img.shields.io/badge/version-2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

**X4-Translator is a client-side, zero-knowledge tool for encrypting and decrypting text directly in your browser.**

It uses the native Web Crypto API to ensure that your passwords and sensitive data are never sent to any server and never leave your device.

### [➡️ Launch the Application](https://x4translator.netlify.app/insiders/translator.html)

---

## 💡 Features

*   **Zero-Knowledge:** All cryptographic operations happen locally in your browser. Nothing is ever stored or transmitted.
*   **Strong Encryption:** Uses the AES-256-GCM authenticated encryption standard.
*   **Password Hardening:** Employs PBKDF2 to turn your passwords into strong cryptographic keys, making them resistant to brute-force attacks.
*   **Configurable Security:** Allows users to set the PBKDF2 iteration count to balance security with performance.
*   **No Dependencies:** Runs entirely on the browser's built-in, secure Web Crypto API.

---

## 🔐 Security Model

The security of X4-Translator is built on standard, well-vetted cryptographic primitives.

#### Key Derivation
-   **Function:** PBKDF2 (Password-Based Key Derivation Function 2)
-   **Hash Algorithms:** User-selectable SHA-256 or SHA-512.
-   **Salt:** A unique, cryptographically random 16-byte salt is generated for each password every time you encrypt. This salt is stored with the encrypted data.
-   **Iterations:** The number of computational rounds for PBKDF2 is user-configurable. **A higher number is strongly recommended.** A modern default is `600,000` for SHA-256.

#### Encryption
-   **Algorithm:** AES-GCM (Advanced Encryption Standard in Galois/Counter Mode)
-   **Key Size:** 256-bit
-   **Nonce (IV):** A unique, cryptographically random 12-byte nonce is generated for each encryption operation. This is essential for the security of AES-GCM.

> **⚠️ Important Design Note:** The current version (v2) uses a non-standard sequential encryption chain. It derives two keys from two separate passwords and applies four layers of encryption. While functional, a future version will be simplified to a more standard, single-layer model using a combined key for better auditability and performance, without sacrificing security.

---

## 📦 Encrypted Data Format

The encrypted output is a single string with several parts joined by the `|` character. All binary data (salts, IVs, ciphertext) is encoded in **Base64**.

The structure is as follows:

| Part                 | Description                                            | Encoding |
| -------------------- | ------------------------------------------------------ | -------- |
| `x4v2`               | Header indicating the data format version.             | UTF-8    |
| `Salt 1`             | The 16-byte salt for the first password (PBKDF2).      | Base64   |
| `IV 1`               | The 12-byte nonce for the first AES-GCM layer.         | Base64   |
| `Salt 2`             | The 16-byte salt for the second password (PBKDF2).     | Base64   |
| `IV 2`               | The 12-byte nonce for the second AES-GCM layer.        | Base64   |
| `Iterations`         | The number of PBKDF2 iterations used.                  | Base64   |
| `Hash Algorithm`     | The hash function used (e.g., "SHA-256").              | Base64   |
| `Final Ciphertext`   | The final, multi-layered encrypted data.               | Base64   |

---

## 🚀 Project Roadmap & Security Improvements

This project is actively being improved. The following are key priorities:

*   [ ] **Set Secure Defaults:** Increase the default PBKDF2 iteration count to a minimum of `600,000`.
*   [ ] **Implement Content-Security-Policy (CSP):** Add a strict CSP header to prevent XSS and other injection attacks.
*   [ ] **Simplify Crypto Model:** Refactor the encryption logic to use a single layer of AES-GCM with a combined key for better standardization and auditability.
*   [ ] **Formal Security Audit:** Seek a review from third-party security professionals to formally verify the implementation.

---

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
