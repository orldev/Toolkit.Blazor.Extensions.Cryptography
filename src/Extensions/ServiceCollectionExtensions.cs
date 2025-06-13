using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Toolkit.Blazor.Extensions.Cryptography.Interfaces;
using Toolkit.Cryptography.Entities;
using Toolkit.Cryptography.Interfaces;

namespace Toolkit.Blazor.Extensions.Cryptography.Extensions;

/// <summary>
/// Provides extension methods for <see cref="IServiceCollection"/> to configure cryptographic services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds JavaScript-compatible asymmetric encryption services to the dependency injection container.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="options">An optional action to configure <see cref="AsymCryptoOpts"/>. 
    /// If not provided, defaults to 2048-bit modulus and SHA-256 hashing.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    /// <example>
    /// <code>
    /// // Using default options
    /// services.AddJsAsymmetricCipher();
    /// 
    /// // With custom options
    /// services.AddJsAsymmetricCipher(options => 
    /// {
    ///     options.ModulusLengthInBits = 4096;
    ///     options.HashMethod = HashAlgo.SHA512;
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddJsAsymmetricCipher(
        this IServiceCollection services, 
        Action<AsymCryptoOpts>? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure(options ??= o =>
        {
            o.ModulusLengthInBits = 2048;
            o.HashMethod = HashAlgo.SHA256;
        });
        services.TryAddSingleton<IJsAsymmetricCipher, JsAsymmetricCipher>();
        return services;
    }
    
    /// <summary>
    /// Adds JavaScript-compatible symmetric encryption services to the dependency injection container.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="options">An optional action to configure <see cref="SymCryptoOpts"/>.
    /// If not provided, defaults to a test passphrase and IV/salt values.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> is null.</exception>
    /// <remarks>
    /// WARNING: The default options use insecure values for demonstration purposes.
    /// Always provide secure values in production environments.
    /// </remarks>
    /// <example>
    /// <code>
    /// // Using default options (not recommended for production)
    /// services.AddJsSymmetricCipher();
    /// 
    /// // With secure options
    /// services.AddJsSymmetricCipher(options => 
    /// {
    ///     options.Passphrase = Configuration["Crypto:Key"];
    ///     options.IV = Configuration["Crypto:IV"];
    ///     options.Salt = Configuration["Crypto:Salt"];
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddJsSymmetricCipher(
        this IServiceCollection services, 
        Action<SymCryptoOpts>? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure(options ??= o =>
        {
            o.Passphrase = "123456";
            o.IV = "abcede0123456789";
            o.Salt = "abcede0123456789";
        });
        services.TryAddSingleton<ISymmetricCipher, JsSymmetricCipher>();
        return services;
    }
    
    /// <summary>
    /// Adds JavaScript-compatible symmetric encryption services to the dependency injection container
    /// with configuration loaded from the specified configuration section.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <param name="configuration">The configuration section containing <see cref="SymCryptoOpts"/> values.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="services"/> or <paramref name="configuration"/> is null.</exception>
    /// <example>
    /// <code>
    /// // appsettings.json:
    /// // {
    /// //   "Cryptography": {
    /// //     "Passphrase": "secure-key-here",
    /// //     "IV": "unique-iv-value",
    /// //     "Salt": "unique-salt-value"
    /// //   }
    /// // }
    /// 
    /// services.AddJsSymmetricCipher(Configuration.GetSection("Cryptography"));
    /// </code>
    /// </example>
    public static IServiceCollection AddJsSymmetricCipher(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure<SymCryptoOpts>(configuration.GetSection("Cryptography"));
        services.TryAddSingleton<ISymmetricCipher, JsSymmetricCipher>();
        return services;
    }
}