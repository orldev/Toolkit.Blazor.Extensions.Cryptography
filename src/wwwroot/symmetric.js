/**
 * Derives a cryptographic key from a passphrase using PBKDF2 (Password-Based Key Derivation Function 2)
 *
 * @param {string} passphrase - The secret passphrase for key derivation (UTF-8 encoded)
 * @param {string} hash - The hash algorithm to use (e.g., 'SHA-256', 'SHA-512')
 * @param {number} iterations - Number of PBKDF2 iterations (recommended ≥ 100,000 for security)
 * @param {Uint8Array} salt - Cryptographic salt (should be 16+ random bytes, stored with ciphertext)
 * @param {number} desiredKeyLength - Desired key length in bytes (e.g., 32 for AES-256)
 * @returns {Promise<CryptoKey>} Derived key configured for AES-GCM operations
 * @throws {Error} If Web Crypto API operations fail or parameters are invalid
 */
async function deriveKeyFromPassword(passphrase, hash, iterations, salt, desiredKeyLength) {
    const buffer = new TextEncoder('utf-8').encode(passphrase);

    const key = await crypto.subtle.importKey(
        'raw',
        buffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey'],
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: {name: hash},
            iterations,
            salt,
        },
        key,
        {
            name: 'AES-GCM',
            length: desiredKeyLength * 8, // Convert bytes to bits
        },
        false,
        ['encrypt', 'decrypt'],
    );
}

/**
 * Encrypts data using AES-GCM with a key derived from a passphrase
 *
 * The output format is: [salt][iv][ciphertext]
 *
 * @param {Uint8Array} data - The plaintext data to encrypt
 * @param {Object} encryptedParams - Encryption parameters object
 * @param {string} encryptedParams.passphrase - The secret passphrase for key derivation
 * @param {string} encryptedParams.hashAlgorithm - The hash algorithm for PBKDF2 (e.g., 'SHA-256')
 * @param {number} encryptedParams.iterations - Number of PBKDF2 iterations
 * @param {Uint8Array} encryptedParams.salt - Cryptographic salt (16+ random bytes recommended)
 * @param {number} encryptedParams.desiredKeyLength - Key length in bytes (e.g., 32 for AES-256)
 * @param {Uint8Array} encryptedParams.iv - Initialization vector (12-16 random bytes recommended for AES-GCM)
 * @returns {Promise<Uint8Array>} Concatenated array containing salt, IV, and encrypted data
 * @throws {Error} If encryption fails or parameters are invalid
 */
export async function encrypt(data, encryptedParams) {
    const { passphrase, hashAlgorithm, iterations, salt, desiredKeyLength, iv } = encryptedParams;
    
    const privateKey = await deriveKeyFromPassword(passphrase, hashAlgorithm, iterations, salt, desiredKeyLength);
    const encrypted = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
            tagLength: 128, // Standard tag length for AES-GCM
        },
        privateKey,
        data,
    );

    const bytes = new Uint8Array(encrypted);
    let buff = new Uint8Array(salt.byteLength + iv.byteLength + encrypted.byteLength);
    buff.set(salt, 0);
    buff.set(iv, salt.byteLength);
    buff.set(bytes, salt.byteLength + iv.byteLength);
    return buff;
}

/**
 * Decrypts data that was encrypted with AES-GCM using a key derived from a passphrase
 *
 * Expects input format: [salt][iv][ciphertext]
 *
 * @param {Uint8Array} data - The encrypted data (including salt and IV prepended)
 * @param {Object} encryptedParams - Decryption parameters object
 * @param {string} encryptedParams.passphrase - The secret passphrase for key derivation
 * @param {string} encryptedParams.hashAlgorithm - The hash algorithm used in PBKDF2
 * @param {number} encryptedParams.iterations - Number of PBKDF2 iterations used
 * @param {Uint8Array} encryptedParams.salt - Cryptographic salt (must match encryption salt)
 * @param {number} encryptedParams.desiredKeyLength - Key length in bytes (must match encryption)
 * @param {Uint8Array} encryptedParams.iv - Initialization vector (must match encryption IV)
 * @returns {Promise<Uint8Array>} The decrypted data as a Uint8Array
 * @throws {Error} If decryption fails, authentication fails, or parameters are invalid
 */
export async function decrypt(data, encryptedParams) {
    const { passphrase, hashAlgorithm, iterations, salt, desiredKeyLength, iv } = encryptedParams;
    const ec = data.slice(salt.byteLength + iv.byteLength);

    const decrypted = await window.crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128,
        },
        await deriveKeyFromPassword(passphrase, hashAlgorithm, iterations, salt, desiredKeyLength),
        ec
    );

    return new Uint8Array(decrypted);
}