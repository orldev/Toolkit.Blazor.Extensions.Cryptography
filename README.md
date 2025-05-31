# Toolkit.Blazor.Extensions.Cryptography 

A Blazor extension providing JavaScript-compatible symmetric and asymmetric cryptography operations through Web Crypto API interop.

## Features

- **Symmetric Encryption** (AES-based)
  - Encrypt/decrypt strings with automatic Base64 conversion
  - Configurable passphrase, IV, and salt
  - JavaScript-compatible output

- **Asymmetric Encryption** (RSA-OAEP)
  - Generate key pairs
  - Encrypt with public key
  - Decrypt with private key
  - Configurable modulus length and hash algorithm

## Installation

Add the package to your Blazor project:

```bash
dotnet add package Snail.Toolkit.Blazor.Extensions.Cryptography
```

## Configuration

### Symmetric Encryption Setup

Choose one of these configuration methods:

1. **Programmatic configuration**:
```csharp
builder.Services.AddJsSymmetricCipher(o =>
{
    o.Passphrase = "secure-passphrase-here";
    o.IV = "unique-iv-value-16bytes";
    o.Salt = "unique-salt-value-16bytes";
    o.Iterations = 1000;
    o.DesiredKeyLength = 32; // 256 bits
    o.HashMethod = HashAlgo.SHA512;
});
```

2. **Configuration-based** (appsettings.json):
```csharp
builder.Services.AddJsSymmetricCipher(builder.Configuration);
```

3. **Default values** (for development only):
```csharp
builder.Services.AddJsSymmetricCipher();
```

### Asymmetric Encryption Setup
```csharp
builder.Services.AddJsAsymmetricCipher(o =>
{
    o.ModulusLengthInBits = 4096;
    o.HashMethod = HashAlgo.SHA512;
});
```

### Sample appsettings.json
```json
{
  "Cryptography": {
    "Passphrase": "secure-passphrase-here",
    "IV": "unique-iv-value-16bytes",
    "Salt": "unique-salt-value-16bytes",
    "Iterations": 1000,
    "DesiredKeyLength": 32,
    "HashMethod": "SHA512"
  }
}
```

## Usage

### Symmetric Encryption

```csharp
public class MyService
{
    private readonly ISymmetricCipher _cipher;

    public MyService(ISymmetricCipher cipher)
    {
        _cipher = cipher;
    }

    public async Task<string> SecureOperation(string sensitiveData)
    {
        // Encrypt
        var encrypted = await _cipher.EncryptToBase64Async(sensitiveData);
        
        // Decrypt
        var decrypted = await _cipher.DecryptFromBase64Async(encrypted);
        
        return decrypted;
    }
}
```

### Asymmetric Encryption

```csharp
public class MySecureService
{
    private readonly IJsAsymmetricCipher _cipher;

    public MySecureService(IJsAsymmetricCipher cipher)
    {
        _cipher = cipher;
    }

    public async Task<(byte[] encrypted, string privateKey)> EncryptData(string data)
    {
        var result = await _cipher.EncryptAsync(data);
        return (result.EncryptedData, result.PrivateKey);
    }

    public async Task<string> DecryptData(string privateKey, byte[] encrypted)
    {
        return await _cipher.DecryptAsync(privateKey, encrypted);
    }
}
```

## Security Considerations

### Supported Hash Algorithms
- SHA1 (legacy)
- SHA256
- SHA384
- SHA512

### Unsupported Algorithms (will throw exceptions)
- MD5 (insecure)
- SHA3 variants (not compatible with Web Crypto API)

### Best Practices
1. Always use strong passphrases (min 16 chars)
2. Generate unique IVs for each encryption operation
3. Store private keys securely
4. Use at least SHA256 for hashing
5. Prefer 4096-bit keys for asymmetric encryption

## JavaScript Interop

The library uses these JavaScript modules from your `wwwroot`:
- `/_content/Snail.Toolkit.Blazor.Extensions.Cryptography/symmetric.js`
- `/_content/Snail.Toolkit.Blazor.Extensions.Cryptography/asymmetric.js`

## License

Toolkit.Blazor.Extensions.Cryptography is a free and open source project, released under the permissible [MIT license](LICENSE).