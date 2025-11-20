# Secure Vault Hybrid Encryption Demo

## 🔒 Secure Vault: Hybrid Encryption, PBKDF2 Key Derivation, and Data Integrity Analysis

This project is a demonstration of a robust, multi-layered file encryption system implemented as a client-server web application. It showcases a hybrid cryptographic approach, combining the efficiency of symmetric encryption (AES-GCM) for bulk data with the security of asymmetric encryption (RSA-OAEP) for key management. Furthermore, it integrates PBKDF2 for strong password-based key derivation and SHA-256 hashing for data integrity verification.

The goal is to provide a clear, functional example of how to implement end-to-end file security in a web environment, emphasizing client-side encryption and authenticated server-side key management.

-----

## ✨ Features

**Hybrid Encryption:** Files are encrypted with a unique AES-256-GCM key per file, which is then securely wrapped (encrypted) by the server's public RSA-OAEP key.

**Strong Password Hashing (PBKDF2):** Uses PBKDF2 (100,000 iterations, SHA-256 hash, 16-byte salt) to derive strong keys from user passwords, protecting against brute-force attacks.

**Data Integrity:** SHA-256 hash of the original file content is computed and verified upon decryption to ensure data has not been tampered with or corrupted.

**Client-Side Cryptography:** All file encryption and decryption operations (AES-GCM, PBKDF2 key derivation, RSA key wrapping preparation) are performed directly in the user's browser using the Web Crypto API.

**Server-Side Key Management:** The Node.js server is responsible for unwrapping the AES key using its private RSA key and securely storing it, only releasing it after client-side password verification.

**Secure Communication:** All client-server communication is assumed to be over a secure channel (TLS/HTTPS).

**Robust Base64 Handling:** Includes fixes for common Base64 encoding/decoding issues when transmitting cryptographic components via URLs.

-----

## 🚀 Getting Started

Follow these steps to set up and run the Secure Vault demo on your local machine.

### Prerequisites

  * Node.js (LTS version recommended)
  * npm (comes with Node.js)

### 1\. Clone the Repository

```bash
git clone https://github.com/Kavya132003/secure-vault-hybrid-encryption-demo
cd secure-vault-hybrid-encryption-demo
```

### 2\. Install Dependencies

Navigate to the project root and install the Node.js server dependencies:

```bash
npm install
```

### 3\. Generate RSA Key Pair

The server requires an RSA public/private key pair. We'll generate a 2048-bit key pair and encrypt the private key with a passphrase.

  * Choose a strong passphrase** for your private key. This will be stored in your `.env` file.

  * Run the key generation script:

    ```bash
    npm run generate-keys
    ```

    You will be prompted to enter a passphrase for your private key.Remember this passphrase, as it will be used in the next step.

    This script will create two files in your project root:

      * `server.public.pem`
      * `server.private.pem` (encrypted with your passphrase)

### 4\. Run the Server

Start the Node.js server:

```bash
npm start
```

You should see output similar to:

```
Private Key PEM file content loaded successfully.
Server running on http://localhost:3000
API Endpoints are ready: /api/public-key, /api/upload, /api/download/:fileId
```

### 5\. Access the Frontend

Open your web browser and navigate to:

```
http://localhost:3000
```

-----

## 📝 How to Use

### Encrypt & Upload

1.  **Select File:** Click "Choose File" and select any file from your computer.
2.  **Set Password:** Enter a password in the "Set Password" field. This password is crucial for decrypting the file later.
3.  **Encrypt & Upload File:** Click the "Encrypt & Upload File" button.
      * The client will perform PBKDF2, AES-GCM encryption, RSA key wrapping, and integrity hashing.
      * The encrypted components will be sent to the server.
      * Upon success, a **File ID** will be displayed in the "Upload Status" and automatically populated in the "File ID" field of the Download section.

### Decrypt & Download

1.  **File ID:** The File ID from your upload should automatically be in the "File ID" field. If not, copy it from the upload status.
2.  **Password:** Enter the *exact same password* you used during the upload process.
3.  **Download & Decrypt:** Click the "Download & Decrypt" button.
      * The client will retrieve encrypted components from the server.
      * It will perform PBKDF2 again to verify your password against the stored hash.
      * If the password is correct, it will request the decrypted AES key from the server (which was unwrapped server-side).
      * The client will then decrypt the file and verify its integrity.
      * Upon success, the original file will be downloaded to your browser.

-----

## 🛠️ Technology Stack

  * **Frontend:**
      * HTML, CSS, JavaScript
      * Web Crypto API (for all cryptographic operations)
  * **Backend:**
      * Node.js
      * Express.js (web framework)
      * Node.js `crypto` module (for server-side RSA decryption)
      * `dotenv` (for environment variables)
      * `cors` (for Cross-Origin Resource Sharing)

-----

## 🛡️ Security Considerations & Demo Limitations

This project is a **demonstration** and includes certain simplifications for clarity. For a production environment, additional security measures would be required:

**Server-Side Storage:** The current demo uses in-memory storage (`storage` object) for encrypted files and keys. A real-world application would require a robust, secure database or dedicated key management system (KMS).

**Private Key Handling:** While the server's private key is encrypted with a passphrase, in a production system, it should be secured in a hardware security module (HSM) or a cloud KMS.

**User Management:** This demo lacks a proper user authentication/authorization system beyond the password hash check. A real application would integrate user accounts, access control, and session management.

**TLS/HTTPS:** While the communication path is labeled as TLS, you should always deploy such an application over HTTPS in a production environment.

**Error Handling:** Error handling is basic. A production application would have more comprehensive error logging and user feedback.

-----

## ✍️ Contribution

Contributions are welcome\! If you find bugs or have suggestions for improvements, please open an issue or submit a pull request.

-----

## 📄 License

This project is open-source

-----