using Microsoft.Extensions.Options;
using Microsoft.JSInterop;
using Toolkit.Blazor.Extensions.Cryptography.Entities;
using Toolkit.Blazor.Extensions.Cryptography.Interfaces;
using Toolkit.Cryptography.Entities;

namespace Toolkit.Blazor.Extensions.Cryptography;

/// <summary>
/// Provides JavaScript-compatible asymmetric encryption and decryption operations
/// by leveraging the Web Crypto API through JS interop.
/// </summary>
/// <remarks>
/// <para>
/// This implementation uses a JavaScript module loaded from "_content/Snail.Toolkit.Blazor.Extensions.Cryptography/asymmetric.js"
/// to perform RSA-OAEP encryption/decryption that is consistent between .NET and JavaScript environments.
/// </para>
/// <para>
/// The class implements <see cref="IAsyncDisposable"/> to properly clean up the JavaScript module reference.
/// </para>
/// </remarks>
/// <param name="jSRuntime">The JS runtime for interop operations</param>
/// <param name="options">Configuration options for the cryptographic operations</param>
public class JsAsymmetricCipher(IJSRuntime jSRuntime, IOptions<AsymCryptoOpts> options) : IJsAsymmetricCipher, IAsyncDisposable
{
    private readonly AsymCryptoOpts _options = options.Value;
    private readonly Lazy<Task<IJSObjectReference>> _module = new(() => jSRuntime.InvokeAsync<IJSObjectReference>(
        "import", "./_content/Snail.Toolkit.Blazor.Extensions.Cryptography/asymmetric.js").AsTask());
    
    /// <summary>
    /// Asynchronously encrypts the specified clear text using RSA-OAEP with a newly generated key pair.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt</param>
    /// <returns>
    /// An <see cref="EncryptionResult"/> containing the encrypted data and private key,
    /// or null if encryption fails.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clearText"/> is null or empty</exception>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    /// <example>
    /// <code>
    /// var cipher = new JsJsAsymmetricCipher(jSRuntime, Options.Create(new AsymCryptoOpts()));
    /// var result = await cipher.EncryptAsync("secret message");
    /// </code>
    /// </example>
    public async Task<EncryptionResult?> EncryptAsync(string clearText)
    {
        var module = await _module.Value;
        return await module.InvokeAsync<EncryptionResult>("encrypt", clearText, new
        {
            _options.ModulusLengthInBits,
            HashAlgorithm = $"{_options.HashMethod:D}"
        });
    }

    /// <summary>
    /// Asynchronously decrypts the specified encrypted data using the provided private key.
    /// </summary>
    /// <param name="privateKey">The private key in Base64-encoded PKCS8 format</param>
    /// <param name="encrypted">The encrypted data to decrypt</param>
    /// <returns>The decrypted plaintext string</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="privateKey"/> or <paramref name="encrypted"/> is null</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="privateKey"/> is malformed</exception>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails</exception>
    public async Task<string> DecryptAsync(string privateKey, byte[] encrypted)
    {
        var module = await _module.Value;
        return await module.InvokeAsync<string>("decrypt", privateKey, encrypted, $"{_options.HashMethod:D}");
    }

    /// <summary>
    /// Calculates the maximum chunk size for encryption based on the current configuration.
    /// </summary>
    /// <returns>
    /// The maximum number of bytes that can be encrypted in a single chunk,
    /// or -1 if the hash algorithm is not recognized.
    /// </returns>
    /// <remarks>
    /// The chunk size is calculated as: (modulusLengthInBytes) - 2*(hashLengthInBytes) - 2
    /// This follows the RSA-OAEP padding requirements.
    /// </remarks>
    private int GetMaxChunkSize()
    {
        // TODO: fix
        if (!Enum.TryParse<HashAlgoLengths>(_options.HashMethod.ToString(), out var result))
            return -1;
        
        var modulusLengthBytes = _options.ModulusLengthInBits / 8;
        return modulusLengthBytes - 2 * (int)result - 2;
    }

    /// <summary>
    /// Asynchronously disposes the JavaScript module reference.
    /// </summary>
    /// <remarks>
    /// This method should be called when the cipher is no longer needed to prevent memory leaks.
    /// </remarks>
    public async ValueTask DisposeAsync()
    {
        if (_module.IsValueCreated)
        {
            var module = await _module.Value;
            await module.DisposeAsync();
        }
    }
}