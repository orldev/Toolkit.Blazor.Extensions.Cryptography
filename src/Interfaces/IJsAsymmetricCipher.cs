using Toolkit.Blazor.Extensions.Cryptography.Entities;

namespace Toolkit.Blazor.Extensions.Cryptography.Interfaces;

/// <summary>
/// Provides JavaScript-compatible asymmetric encryption and decryption operations.
/// </summary>
/// <remarks>
/// <para>
/// This interface defines methods for performing RSA encryption that is compatible with
/// JavaScript implementations using the Web Crypto API. It supports the RSA-OAEP algorithm.
/// </para>
/// <para>
/// Implementations should be thread-safe as they may be used concurrently by multiple callers.
/// </para>
/// </remarks>
public interface IJsAsymmetricCipher
{
    /// <summary>
    /// Asynchronously encrypts the specified clear text using a newly generated RSA key pair.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt. Cannot be null or empty.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains:
    /// <list type="bullet">
    ///   <item><description><see cref="EncryptionResult.EncryptedData"/> - The encrypted data as a byte array</description></item>
    ///   <item><description><see cref="EncryptionResult.PrivateKey"/> - The private key in Base64-encoded PKCS8 format needed for decryption</description></item>
    /// </list>
    /// Returns null if encryption fails.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clearText"/> is null or empty.</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails due to cryptographic operations.</exception>
    /// <example>
    /// <code>
    /// var cipher = serviceProvider.GetRequiredService&lt;IJsAsymmetricCipher&gt;();
    /// var result = await cipher.EncryptAsync("secret message");
    /// // Store result.PrivateKey securely
    /// // Send result.EncryptedData to recipient
    /// </code>
    /// </example>
    Task<EncryptionResult?> EncryptAsync(string clearText);

    /// <summary>
    /// Asynchronously decrypts the specified encrypted data using the provided private key.
    /// </summary>
    /// <param name="privateKey">The private key in Base64-encoded PKCS8 format.</param>
    /// <param name="encrypted">The encrypted data to decrypt.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains
    /// the decrypted plaintext string.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="privateKey"/> or <paramref name="encrypted"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="privateKey"/> is malformed.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails due to cryptographic operations.</exception>
    /// <example>
    /// <code>
    /// var cipher = serviceProvider.GetRequiredService&lt;IJsAsymmetricCipher&gt;();
    /// string decrypted = await cipher.DecryptAsync(storedPrivateKey, receivedEncryptedData);
    /// </code>
    /// </example>
    Task<string> DecryptAsync(string privateKey, byte[] encrypted);
}