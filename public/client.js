const API_URL = 'http://localhost:3000/api';
let PUBLIC_RSA_KEY = null;
const KDF_ITERATIONS = 100000; // Strong iteration count for PBKDF2

// --- Utility Functions ---

const updateStatus = (elementId, message, className = 'loading') => {
    const el = document.getElementById(elementId);
    el.innerHTML = message;
    el.className = className;
};

const arrayBufferToBase64 = (buffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    // Note: btoa always generates standard Base64 (+, /, and = padding)
    return btoa(binary);
};

// --- FIX APPLIED HERE: Robust Base64 decoding ---
const base64ToArrayBuffer = (base64) => {
    // 1. Normalize Base64: Replace URL-safe chars with standard chars
    let safeBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    
    // 2. Pad the string: Add '=' padding if length is not a multiple of 4
    while (safeBase64.length % 4) {
        safeBase64 += '=';
    }

    // 3. Decode
    try {
        const binary_string = atob(safeBase64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (e) {
        console.error("Base64 Decode Error:", e);
        // Throw a clearer error if atob still fails after normalization/padding
        throw new Error("Failed to decode Base64 string even after cleanup. Data corruption suspected.");
    }
};

// --- PBKDF2 Key Derivation Function (KDF) ---

async function deriveKeyAndHash(password, salt) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    // 1. Import password as a CryptoKey
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey", "deriveBits"]
    );

    // 2. Derive a 256-bit key
    const derivedKey = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: KDF_ITERATIONS,
            hash: "SHA-256",
        },
        baseKey,
        256 // 256 bits (32 bytes)
    );
    
    // 3. Hash the derived key to create a server-verifiable password hash
    const passwordHashBuffer = await window.crypto.subtle.digest('SHA-256', derivedKey);
    const passwordHash = arrayBufferToBase64(passwordHashBuffer);

    return { derivedKey, passwordHash };
}


// --- Initial Setup: Fetch Server's RSA Public Key ---

async function fetchPublicKey() {
    try {
        const response = await fetch(`${API_URL}/public-key`);
        const data = await response.json();
        const pemKey = data.publicKey;
        
        const keyBase64 = pemKey
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\s/g, '');

        const keyBuffer = base64ToArrayBuffer(keyBase64);

        PUBLIC_RSA_KEY = await window.crypto.subtle.importKey(
            "spki",
            keyBuffer,
            { name: "RSA-OAEP", hash: { name: "SHA-256" } },
            true,
            ["encrypt"]
        );

        document.getElementById('uploadButton').disabled = false;
        document.getElementById('downloadButton').disabled = false;
        updateStatus('uploadStatus', 'Status: Public key loaded. Ready to upload.', 'success');
    } catch (e) {
        updateStatus('uploadStatus', `ERROR: Could not fetch public key. Is the server running? (${e.message})`, 'error');
        console.error("Public Key Load Error:", e);
    }
}

fetchPublicKey();

// --- 1. ENCRYPTION (AES + RSA Hybrid + PBKDF2) ---

async function encryptFile(file, password, rsaKey) {
    const startTotal = performance.now();
    
    // 1. Generate new 16-byte Salt for PBKDF2
    const passwordSalt = window.crypto.getRandomValues(new Uint8Array(16)); 

    // 2. PBKDF2 Key Derivation
    updateStatus('uploadStatus', 'Deriving key from password (PBKDF2, 100k iterations)...', 'loading');
    const { derivedKey, passwordHash } = await deriveKeyAndHash(password, passwordSalt);
    
    // 3. Read File Content and Calculate SHA-256 Hash
    const fileBuffer = await file.arrayBuffer();
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', fileBuffer);
    const fileHash = arrayBufferToBase64(hashBuffer);

    // 4. Generate AES Key and IV
    const aesKey = await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 5. AES ENCRYPTION (Bulk data encryption)
    const startAES = performance.now();
    const encryptedFileBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        aesKey,
        fileBuffer
    );
    const endAES = performance.now();

    // Separate Ciphertext and Auth Tag
    const bufferBytes = new Uint8Array(encryptedFileBuffer);
    const authTag = bufferBytes.slice(bufferBytes.length - 16);
    const cipherText = bufferBytes.slice(0, bufferBytes.length - 16);
    
    // 6. Export AES Key as raw bytes
    const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

    // 7. RSA ENCRYPTION (Securing the small AES Key)
    const startRSA = performance.now();
    const encryptedAESKeyBuffer = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP", hash: "SHA-256" },
        rsaKey,
        rawAesKey
    );
    const endRSA = performance.now();
    const endTotal = performance.now();
    
    return {
        encryptedFile: arrayBufferToBase64(cipherText),
        encryptedAESKey: arrayBufferToBase64(encryptedAESKeyBuffer),
        iv: arrayBufferToBase64(iv),
        authTag: arrayBufferToBase64(authTag),
        fileHash: fileHash, 
        passwordHash: passwordHash, // NEW: Store hash of derived key for password verification
        passwordSalt: arrayBufferToBase64(passwordSalt), // NEW: Store salt to re-derive the key
        metrics: {
            aesTime: (endAES - startAES).toFixed(2),
            rsaTime: (endRSA - startRSA).toFixed(2),
            totalTime: (endTotal - startTotal).toFixed(2),
            fileSize: file.size
        }
    };
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const passwordInput = document.getElementById('uploadPasswordInput');
    const file = fileInput.files[0];
    const password = passwordInput.value;

    if (!file || !PUBLIC_RSA_KEY) {
        updateStatus('uploadStatus', 'Please select a file and ensure the public key is loaded.', 'error');
        return;
    }
    if (password.length < 4) {
        updateStatus('uploadStatus', 'Please enter a password (min 4 characters).', 'error');
        return;
    }

    updateStatus('uploadStatus', `Encrypting <span class="metric-value">${file.name}</span> (Size: <span class="metric-value">${(file.size / 1024).toFixed(2)} KB</span>)...`, 'loading');
    document.getElementById('uploadButton').disabled = true;

    try {
        const encryptionResult = await encryptFile(file, password, PUBLIC_RSA_KEY);
        const { metrics, ...payload } = encryptionResult;

        updateStatus('uploadStatus', 'Encryption complete. Uploading encrypted data...', 'loading');

        // POST request to the server
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                fileName: file.name,
                ...payload
            }),
        });

        const result = await response.json();
        
        if (response.ok) {
            updateStatus('uploadStatus', `
                <span class="success">✅ Success!</span> File ID: <b>${result.fileId}</b>.<br><br>
                <b>Performance Metrics:</b><br>
                - Total Processing Time: <span class="metric-value">${metrics.totalTime} ms</span><br>
                - PBKDF2 Key Derivation: <span class="metric-value">${(metrics.totalTime - metrics.aesTime - metrics.rsaTime).toFixed(2)} ms</span><br>
                - AES Bulk Encryption: <span class="metric-value">${metrics.aesTime} ms</span><br>
                - RSA Key Encryption: <span class="metric-value">${metrics.rsaTime} ms</span><br>
                <i style="color: #a0a0a0;">(PBKDF2 is deliberately slow to thwart brute-force attacks.)</i>
            `, 'success');
            document.getElementById('fileIdInput').value = result.fileId;
        } else {
            updateStatus('uploadStatus', `❌ Upload Failed: ${result.error}`, 'error');
        }

    } catch (e) {
        updateStatus('uploadStatus', `FATAL ERROR during upload: ${e.message}`, 'error');
        console.error(e);
    } finally {
        document.getElementById('uploadButton').disabled = false;
    }
}

// --- 2. DECRYPTION (Hybrid Decryption + PBKDF2) ---

async function decryptFile(encryptedData, password) {
    const startTotal = performance.now();
    updateStatus('downloadStatus', '1/4: Running client-side PBKDF2 verification...', 'loading');
    
    // 1. Client-side Password Verification & Key Derivation
    // Fails here if passwordSalt is malformed Base64 (before the fix)
    let passwordSaltBuffer;
    try {
        passwordSaltBuffer = base64ToArrayBuffer(encryptedData.passwordSalt);
    } catch(e) {
        updateStatus('downloadStatus', `❌ Failed to decode password salt. Corrupted Base64: ${e.message}`, 'error');
        return;
    }
    
    // We re-derive the key and check the hash against the stored hash
    const { passwordHash: calculatedPasswordHash } = await deriveKeyAndHash(password, passwordSaltBuffer);

    if (calculatedPasswordHash !== encryptedData.passwordHash) {
        updateStatus('downloadStatus', '❌ Password Verification Failed! Incorrect password.', 'error');
        return;
    }
    
    // 2. Fetch the decrypted AES key from the server
    updateStatus('downloadStatus', '2/4: Decrypting AES key (Server-side simulation)...', 'loading');
    
    // Keep: URL-encode the Base64 hash for safe transmission
    const encodedPasswordHash = encodeURIComponent(calculatedPasswordHash); 
    
    const keyFetchResponse = await fetch(`${API_URL}/get-decrypted-key/${encryptedData.fileId}?passwordHash=${encodedPasswordHash}`);
    if (!keyFetchResponse.ok) {
        const errorData = await keyFetchResponse.json();
        updateStatus('downloadStatus', `❌ Server Error: ${errorData.error}`, 'error');
        return;
    }
    const { decryptedAESKey } = await keyFetchResponse.json();
    
    // 3. Import the recovered AES Key
    updateStatus('downloadStatus', '3/4: Importing AES key and combining buffers...', 'loading');
    
    let keyBuffer;
    try {
        keyBuffer = base64ToArrayBuffer(decryptedAESKey);
    } catch (e) {
        updateStatus('downloadStatus', `❌ Failed to decode decrypted AES key. Corrupted Base64: ${e.message}`, 'error');
        return;
    }

    const aesKey = await window.crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt"]
    );
    
    let cipherTextBuffer, authTagBuffer;
    try {
        cipherTextBuffer = base64ToArrayBuffer(encryptedData.encryptedFile);
        authTagBuffer = base64ToArrayBuffer(encryptedData.authTag);
    } catch (e) {
        updateStatus('downloadStatus', `❌ Failed to decode file components. Corrupted Base64: ${e.message}`, 'error');
        return;
    }

    const fullCipherBuffer = new Uint8Array(cipherTextBuffer.byteLength + authTagBuffer.byteLength);
    fullCipherBuffer.set(new Uint8Array(cipherTextBuffer), 0);
    fullCipherBuffer.set(new Uint8Array(authTagBuffer), cipherTextBuffer.byteLength);
    
    let decryptedBuffer;
    // 4. AES DECRYPTION
    updateStatus('downloadStatus', '4/4: Performing AES Decryption and Authentication...', 'loading');
    try {
        decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: base64ToArrayBuffer(encryptedData.iv), tagLength: 128 },
            aesKey,
            fullCipherBuffer
        );
    } catch (e) {
        updateStatus('downloadStatus', `❌ AES Decryption Failed: The data is invalid, possibly due to a wrong key or corrupted IV/Auth Tag.`, 'error');
        console.error("Decryption Error:", e);
        return;
    }

    // 5. Integrity Check (SHA-256)
    const calculatedHashBuffer = await window.crypto.subtle.digest('SHA-256', decryptedBuffer);
    const calculatedFileHash = arrayBufferToBase64(calculatedHashBuffer);

    if (calculatedFileHash !== encryptedData.fileHash) {
        updateStatus('downloadStatus', `
            ❌ Integrity Check Failed! File data was corrupted or modified in storage.<br>
            Hash Mismatch Detected.
        `, 'error');
        return;
    }
    
    const endTotal = performance.now();
    const decryptTime = (endTotal - startTotal).toFixed(2);
    
    // 6. Initiate Download
    const blob = new Blob([decryptedBuffer]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = encryptedData.fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    updateStatus('downloadStatus', `
        <span class="success">✅ Decryption Success!</span> File <b>${encryptedData.fileName}</b> downloaded.<br><br>
        <b>Integrity Status:</b> <span class="success">SHA-256 Match Confirmed.</span><br>
        <b>Authentication:</b> <span class="success">PBKDF2 Password Validated.</span><br>
        <b>Decryption Time:</b> <span class="metric-value">${decryptTime} ms</span>
    `, 'success');
}

async function downloadFile() {
    const fileId = document.getElementById('fileIdInput').value.trim();
    const password = document.getElementById('downloadPasswordInput').value;

    if (!fileId) {
        updateStatus('downloadStatus', 'Please enter a valid File ID.', 'error');
        return;
    }
    if (password.length < 4) {
        updateStatus('downloadStatus', 'Please enter the password used for encryption (min 4 characters).', 'error');
        return;
    }

    updateStatus('downloadStatus', `Fetching encrypted components for ID: ${fileId}...`, 'loading');
    document.getElementById('downloadButton').disabled = true;

    try {
        const response = await fetch(`${API_URL}/download/${fileId}`);
        const data = await response.json();

        if (!response.ok) {
            updateStatus('downloadStatus', `❌ Download Failed: ${data.error}`, 'error');
            return;
        }
        
        // Pass all components and the user-provided password
        await decryptFile({...data, fileId}, password); 

    } catch (e) {
        // This catches errors from fetch, JSON parsing, or the decryptFile function throwing after the fix
        updateStatus('downloadStatus', `FATAL ERROR during download/decryption: ${e.message}`, 'error');
        console.error(e);
    } finally {
        document.getElementById('downloadButton').disabled = false;
    }
}