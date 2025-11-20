// server.js
require('dotenv').config(); 
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors'); 

const app = express();
const port = process.env.PORT || 3000;
const KEY_PASSPHRASE = process.env.KEY_PASSPHRASE; // Passphrase for the encrypted private key

app.use(express.json({ limit: '50mb' })); 
app.use(cors());
app.use(express.static('public')); // Serve the frontend files

// --- Load Keys ---
let PRIVATE_KEY_PEM_STRING = null;
try {
    // Read the raw, encrypted PEM file content as a string
    PRIVATE_KEY_PEM_STRING = fs.readFileSync(path.join(__dirname, 'server.private.pem'), 'utf8');
    
    if (!PRIVATE_KEY_PEM_STRING) {
        throw new Error("Private key file is empty.");
    }
    console.log('Private Key PEM file content loaded successfully.');
} catch (error) {
    console.error('Error reading private key PEM file:', error.message);
    process.exit(1); 
}

// Simple in-memory storage for the encrypted files (for demo only)
const storage = {};

// --- Endpoint 1: Get Public Key (For Client Encryption) ---
app.get('/api/public-key', (req, res) => {
    try {
        const publicKey = fs.readFileSync(path.join(__dirname, 'server.public.pem'), 'utf8');
        res.send({ publicKey: publicKey });
    } catch (e) {
        res.status(500).send({ error: 'Could not load public key.' });
    }
});


// --- Endpoint 2: Secure File Upload (Hybrid Decryption) ---
app.post('/api/upload', (req, res) => {
    const { 
        fileName, 
        encryptedFile, 
        encryptedAESKey, 
        iv, 
        authTag, 
        fileHash, 
        passwordHash, // NEW: Hash of the derived key
        passwordSalt  // NEW: Salt for PBKDF2
    } = req.body;

    if (!fileName || !encryptedFile || !encryptedAESKey || !iv || !authTag || !fileHash || !passwordHash || !passwordSalt) {
        return res.status(400).send({ error: 'Missing data fields. All encryption components, integrity hash, password hash, and salt are required.' });
    }

    try {
        // 1. RSA DECRYPTION (Server recovers the AES key)
        const decryptedAESKeyBuffer = crypto.privateDecrypt(
            {
                key: PRIVATE_KEY_PEM_STRING, 
                passphrase: KEY_PASSPHRASE, 
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256',
            },
            Buffer.from(encryptedAESKey, 'base64')
        );
        const decryptedAESKey = decryptedAESKeyBuffer.toString('base64');
        
        // 2. STORE DATA
        const fileId = crypto.randomBytes(4).toString('hex');
        storage[fileId] = {
            fileName,
            encryptedFile,
            encryptedAESKey, 
            decryptedAESKey: decryptedAESKey, // Recovered AES key (used only for the demo endpoint)
            iv,
            authTag,
            fileHash, 
            passwordHash, // Store hash of derived key
            passwordSalt  // Store salt
        };

        console.log(`File received and AES Key decrypted for ${fileName}. ID: ${fileId}`);
        res.send({ message: 'File uploaded and key secured.', fileId });

    } catch (error) {
        console.error('Decryption failed:', error.message);
        res.status(500).send({ error: 'Failed to decrypt the AES key.' });
    }
});


// --- Endpoint 3: File Decryption (For Client Download) ---
app.get('/api/download/:fileId', (req, res) => {
    const { fileId } = req.params;
    const fileData = storage[fileId];

    if (!fileData) {
        return res.status(404).send({ error: 'File not found.' });
    }
    
    // Sends all encrypted components PLUS the integrity and password components back to the client
    res.send({
        fileName: fileData.fileName,
        encryptedFile: fileData.encryptedFile,
        encryptedAESKey: fileData.encryptedAESKey,
        iv: fileData.iv,
        authTag: fileData.authTag,
        fileHash: fileData.fileHash, 
        passwordHash: fileData.passwordHash, // Return the stored hash
        passwordSalt: fileData.passwordSalt  // Return the salt
    });
});


// --- DEMO ENDPOINT: Send Decrypted AES Key (Now requires Password Hash check) ---
app.get('/api/get-decrypted-key/:fileId', (req, res) => {
    const { fileId } = req.params;
    const { passwordHash: clientPasswordHash } = req.query; // Client sends their calculated hash

    const fileData = storage[fileId];

    if (!fileData) {
        return res.status(404).send({ error: 'File not found.' });
    }
    
    // NEW SECURITY CHECK: If the client's calculated hash doesn't match the stored hash, deny access.
    if (!clientPasswordHash || fileData.passwordHash !== clientPasswordHash) {
         // Deny access if the password hash from the client is missing or doesn't match the stored hash.
         return res.status(403).send({ error: 'Password hash mismatch. Access denied to decrypted key.' });
    }
    
    // Only if the hash matches, we send the decrypted key (Demo only!)
    res.send({
        decryptedAESKey: fileData.decryptedAESKey,
    });
});


app.listen(port, () => {
    console.log(`\nServer running on http://localhost:${port}`);
    console.log('API Endpoints are ready: /api/public-key, /api/upload, /api/download/:fileId');
});