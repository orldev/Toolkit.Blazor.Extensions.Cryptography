using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.JSInterop;
using Toolkit.Cryptography.Entities;
using Toolkit.Cryptography.Interfaces;

namespace Toolkit.Blazor.Extensions.Cryptography;

/// <summary>
/// Provides JavaScript-interoperable symmetric encryption and decryption operations
/// using the Web Crypto API through JS interop in Blazor applications.
/// </summary>
/// <remarks>
/// <para>
/// This implementation bridges .NET and JavaScript cryptography by using a JavaScript module
/// loaded from "_content/Snail.Toolkit.Blazor.Extensions.Cryptography/symmetric.js" to perform
/// AES-GCM encryption/decryption with PBKDF2 key derivation, ensuring consistent results
/// across both environments.
/// </para>
/// <para>
/// The encryption process uses the following parameters from <see cref="SymCryptoOpts"/>:
/// <list type="bullet">
///   <item><description>Passphrase for key derivation</description></item>
///   <item><description>Cryptographic salt (random bytes, typically 16+ bytes)</description></item>
///   <item><description>Initialization Vector (IV, 12 bytes recommended for AES-GCM)</description></item>
///   <item><description>PBKDF2 iterations (recommended ≥ 100,000)</description></item>
///   <item><description>Hash algorithm (typically SHA-256 or SHA-512)</description></item>
///   <item><description>Key length (e.g., 32 bytes for AES-256)</description></item>
/// </list>
/// </para>
/// <para>
/// The class implements <see cref="IAsyncDisposable"/> to properly clean up the JavaScript
/// module reference and prevent memory leaks in Blazor applications.
/// </para>
/// <para>
/// Note: All string operations use Unicode (UTF-16) encoding for compatibility with .NET strings.
/// The encrypted output format is: [salt][iv][ciphertext].
/// </para>
/// </remarks>
/// <param name="jSRuntime">The JS runtime instance for interop operations</param>
/// <param name="options">Configuration options for cryptographic operations</param>
public class JsSymmetricCipher(IJSRuntime jSRuntime, IOptions<SymCryptoOpts> options) : ISymmetricCipher, IAsyncDisposable
{
    private readonly SymCryptoOpts _options = options.Value;
    private readonly SemaphoreSlim _jsInteropSemaphore = new(1, 1); 
    private readonly Lazy<Task<IJSObjectReference>> _module = new(() => jSRuntime.InvokeAsync<IJSObjectReference>(
        "import", "./_content/Snail.Toolkit.Blazor.Extensions.Cryptography/symmetric.js").AsTask());
    
    /// <summary>
    /// Asynchronously encrypts the specified plaintext bytes using AES-GCM encryption.
    /// </summary>
    /// <param name="plainText">The plaintext byte array to encrypt (cannot be null or empty)</param>
    /// <returns>
    /// A byte array containing the encrypted data in the format: [salt][iv][ciphertext]
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="plainText"/> is null</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="plainText"/> is empty</exception>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    public async Task<byte[]> EncryptAsync(byte[] plainText) =>
        await JsModuleInvokeAsync<byte[]>("encrypt", plainText);

    /// <summary>
    /// Asynchronously decrypts the specified encrypted data using AES-GCM decryption.
    /// </summary>
    /// <param name="encrypted">
    /// The encrypted data in the format: [salt][iv][ciphertext] (cannot be null or empty)
    /// </param>
    /// <returns>The decrypted plaintext as a byte array</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encrypted"/> is null</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="encrypted"/> is empty</exception>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (including authentication failure)</exception>
    public async Task<byte[]> DecryptAsync(byte[] encrypted) =>
        await JsModuleInvokeAsync<byte[]>("decrypt", encrypted);

    /// <summary>
    /// Asynchronously encrypts the specified plaintext string and returns the result as a Base64 string.
    /// </summary>
    /// <param name="clearText">The plaintext string to encrypt (cannot be null or empty)</param>
    /// <returns>
    /// A Base64-encoded string representing the encrypted data in the format: [salt][iv][ciphertext]
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="clearText"/> is null</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="clearText"/> is empty</exception>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    /// <exception cref="CryptographicException">Thrown when encryption fails</exception>
    public async Task<string> EncryptToBase64Async(string clearText)
    {
        var bytes = Encoding.Unicode.GetBytes(clearText);
        var encrypt = await EncryptAsync(bytes);
        return Convert.ToBase64String(encrypt);
    }

    /// <summary>
    /// Asynchronously decrypts the specified Base64-encoded encrypted string.
    /// </summary>
    /// <param name="encrypted">
    /// The Base64-encoded encrypted data in the format: [salt][iv][ciphertext] (cannot be null or empty)
    /// </param>
    /// <returns>The decrypted plaintext string</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="encrypted"/> is null</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="encrypted"/> is empty</exception>
    /// <exception cref="FormatException">Thrown when the input is not valid Base64</exception>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (including authentication failure)</exception>
    public async Task<string> DecryptFromBase64Async(string encrypted)
    {
        var bytes = Convert.FromBase64String(encrypted);
        var decrypt = await DecryptAsync(bytes);
        return Encoding.Unicode.GetString(decrypt);
    }

    /// <summary>
    /// Helper method to invoke JavaScript module functions with the configured crypto parameters.
    /// </summary>
    /// <typeparam name="T">The expected return type</typeparam>
    /// <param name="name">The name of the JavaScript function to invoke</param>
    /// <param name="value">The value to pass to the function</param>
    /// <returns>The result of the JavaScript operation</returns>
    /// <exception cref="JSException">Thrown when JavaScript interop fails</exception>
    private async ValueTask<T> JsModuleInvokeAsync<T>(string name, object value)
    {
        try
        {
            await _jsInteropSemaphore.WaitAsync().ConfigureAwait(false);
        
            var module = await _module.Value;
            return await module.InvokeAsync<T>(name, value, _options.CreateParams())
                .ConfigureAwait(false);
        }
        finally
        {
            _jsInteropSemaphore.Release();
        }
    }
    
    /// <summary>
    /// Asynchronously disposes the JavaScript module reference.
    /// </summary>
    /// <remarks>
    /// This method should be called when the cipher is no longer needed to properly clean up
    /// the JavaScript module reference and prevent memory leaks in Blazor applications.
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