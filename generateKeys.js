// generateKeys.js (Using Synchronous Functions)
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
require('dotenv').config(); // Keep this to load the .env file

const KEY_PASSPHRASE = process.env.KEY_PASSPHRASE;

if (!KEY_PASSPHRASE) {
    console.error("FATAL: Please set KEY_PASSPHRASE in your .env file before running!");
    process.exit(1);
}

try {
    // Generate Key Pair (Synchronous)
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: KEY_PASSPHRASE 
        }
    });

    // Write Files (Synchronous)
    fs.writeFileSync(path.join(__dirname, 'server.public.pem'), publicKey);
    console.log('✅ Public key generated and saved as server.public.pem');

    fs.writeFileSync(path.join(__dirname, 'server.private.pem'), privateKey);
    console.log('✅ Private key generated and saved as server.private.pem (Encrypted)');

} catch (err) {
    console.error('FATAL ERROR during key generation or file write:', err.message);
    process.exit(1);
}