/**
 * RSA Encryption Module
 *
 * This module provides functions for generating RSA key pairs, encrypting data with public keys,
 * and decrypting data with private keys using the Web Crypto API. All keys are exported/imported
 * in Base64 format for easy storage and transmission.
 *
 * @module RSAEncryption
 */

/**
 * Generates an RSA key pair with specified parameters.
 *
 * @async
 * @function generateKeyPair
 * @param {number} modulusLength - The length of the RSA modulus in bits (e.g., 2048, 4096)
 * @param {number} hash - The SHA hash algorithm to use (e.g., 256, 384, 512)
 * @returns {Promise<Object>} An object containing the public and private keys in Base64 format
 * @throws {Error} If key generation fails
 * @example
 * const { publicKey, privateKey } = await generateKeyPair(2048, 256);
 */
async function generateKeyPair(modulusLength, hash) {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: modulusLength,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                hash: { name: `SHA-${hash}` }
            },
            true,
            ["encrypt", "decrypt"]
        );

        return {
            publicKey: await exportPublicKey(keyPair.publicKey),
            privateKey: await exportPrivateKey(keyPair.privateKey)
        };
    } catch (error) {
        console.error("Key generation failed:", error);
        throw error;
    }
}

/**
 * Exports a public key to Base64 SPKI format.
 *
 * @async
 * @function exportPublicKey
 * @param {CryptoKey} key - The public CryptoKey object to export
 * @returns {Promise<string>} The public key in Base64-encoded SPKI format
 * @throws {Error} If key export fails
 */
async function exportPublicKey(key) {
    try {
        const exported = await window.crypto.subtle.exportKey("spki", key);
        return arrayBufferToBase64(exported);
    } catch (error) {
        console.error("Public key export failed:", error);
        throw error;
    }
}

/**
 * Exports a private key to Base64 PKCS8 format.
 *
 * @async
 * @function exportPrivateKey
 * @param {CryptoKey} key - The private CryptoKey object to export
 * @returns {Promise<string>} The private key in Base64-encoded PKCS8 format
 * @throws {Error} If key export fails
 */
async function exportPrivateKey(key) {
    try {
        const exported = await window.crypto.subtle.exportKey("pkcs8", key);
        return arrayBufferToBase64(exported);
    } catch (error) {
        console.error("Private key export failed:", error);
        throw error;
    }
}

/**
 * Encrypts data using a newly generated RSA public key.
 *
 * @async
 * @function encrypt
 * @param {string} data - The plaintext data to encrypt
 * @param {Object} encryptedParams - Encryption parameters
 * @param {number} encryptedParams.modulusLengthInBits - RSA modulus length (e.g., 2048)
 * @param {number} encryptedParams.hashAlgorithm - SHA hash algorithm (e.g., 256)
 * @returns {Promise<Object>} An object containing the encrypted data as Uint8Array and the private key in Base64
 * @throws {Error} If encryption fails
 * @example
 * const result = await encrypt("secret message", { modulusLengthInBits: 2048, hashAlgorithm: 256 });
 * // result contains { encryptedData: Uint8Array, privateKey: string }
 */
export async function encrypt(data, encryptedParams) {
    try {
        const { modulusLengthInBits, hashAlgorithm } = encryptedParams;
        console.log("encrypt", encryptedParams);
        const { publicKey, privateKey} = await generateKeyPair(modulusLengthInBits, hashAlgorithm);
        // Import the public key
        const key = await importPublicKey(publicKey, hashAlgorithm);

        // Encode the data
        const encodedData = new TextEncoder().encode(data);

        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            key,
            encodedData
        );
        return {
            encryptedData: new Uint8Array(encryptedData),
            privateKey: privateKey
        };
    } catch (error) {
        console.error("Encryption failed:", error);
        console.log("Public key used:", publicKeyBase64);
        console.log("Data length:", data?.length);
        throw error;
    }
}

/**
 * Decrypts data using an RSA private key.
 *
 * @async
 * @function decrypt
 * @param {string} privateKey - The private key in Base64-encoded PKCS8 format
 * @param {Uint8Array} data - The encrypted data to decrypt
 * @param {number} hashAlgorithm - The SHA hash algorithm used during encryption (e.g., 256)
 * @returns {Promise<string>} The decrypted plaintext
 * @throws {Error} If decryption fails
 * @example
 * const decrypted = await decrypt(privateKey, encryptedData, 256);
 */
export async function decrypt(privateKey, data, hashAlgorithm) {
    const key = await importPrivateKey(privateKey, hashAlgorithm);
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        key,
        data,
    );
    return new TextDecoder().decode(decrypted);
}

/**
 * Converts an ArrayBuffer to Base64 string.
 *
 * @function arrayBufferToBase64
 * @param {ArrayBuffer} buffer - The binary data to convert
 * @returns {string} Base64-encoded string
 */
function arrayBufferToBase64(buffer) {
    const uint8Array = new Uint8Array(buffer);
    const chunkSize = 0x8000; // Process in 32KB chunks to avoid stack overflow
    const chunks = [];

    for (let i = 0; i < uint8Array.length; i += chunkSize) {
        const chunk = uint8Array.subarray(i, i + chunkSize);
        chunks.push(String.fromCharCode.apply(null, chunk));
    }

    return btoa(chunks.join(''));
}

/**
 * Converts a Base64 string to an ArrayBuffer.
 *
 * @function base64ToArrayBuffer
 * @param {string} base64 - The Base64-encoded string
 * @returns {ArrayBuffer} The binary data
 */
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);

    // Process in chunks for very large strings
    const chunkSize = 0x8000;
    for (let i = 0; i < len; i += chunkSize) {
        const end = Math.min(i + chunkSize, len);
        for (let j = i; j < end; j++) {
            bytes[j] = binaryString.charCodeAt(j);
        }
    }

    return bytes.buffer;
}

/**
 * Imports a public key from Base64 SPKI format.
 *
 * @async
 * @function importPublicKey
 * @param {string} spkiBase64 - The public key in Base64-encoded SPKI format
 * @param {number} hash - The SHA hash algorithm to use (e.g., 256)
 * @returns {Promise<CryptoKey>} The imported public CryptoKey
 */
async function importPublicKey(spkiBase64, hash) {
    const spki = base64ToArrayBuffer(spkiBase64);
    return await window.crypto.subtle.importKey(
        "spki",
        spki,
        {
            name: "RSA-OAEP",
            hash: { name: `SHA-${hash}` }
        },
        true,
        ["encrypt"]
    );
}

/**
 * Imports a private key from Base64 PKCS8 format.
 *
 * @async
 * @function importPrivateKey
 * @param {string} pkcs8Base64 - The private key in Base64-encoded PKCS8 format
 * @param {number} hash - The SHA hash algorithm to use (e.g., 256)
 * @returns {Promise<CryptoKey>} The imported private CryptoKey
 */
async function importPrivateKey(pkcs8Base64, hash) {
    const pkcs8 = base64ToArrayBuffer(pkcs8Base64);
    return await window.crypto.subtle.importKey(
        "pkcs8",
        pkcs8,
        { name: "RSA-OAEP", hash: `SHA-${hash}` },
        true,
        ["decrypt"]
    );
}