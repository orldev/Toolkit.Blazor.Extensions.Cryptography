namespace Toolkit.Blazor.Extensions.Cryptography.Entities;

/// <summary>
/// Represents the result of an encryption operation containing both the encrypted data
/// and the private key needed for decryption.
/// </summary>
/// <remarks>
/// This immutable record type is typically returned from encryption operations where
/// a new key pair is generated for each encryption. The private key is provided in
/// Base64-encoded PKCS8 format for storage or transmission.
/// </remarks>
/// <param name="EncryptedData">The encrypted byte array</param>
/// <param name="PrivateKey">The private key in Base64-encoded PKCS8 format</param>
public record EncryptionResult(byte[] EncryptedData, string PrivateKey);