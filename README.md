# SecureStore

> Enterprise-grade PowerShell module for secure local secret management and certificate generation

SecureStore provides a centralized, secure solution for managing passwords, API keys, and certificates across Windows and cross-platform PowerShell environments. With authenticated AES-256 encryption, safe file handling, and an organized folder structure, it is well suited for DevOps workflows, automation scripts, and enterprise deployments.

## Key Features

- **AES-256 Authenticated Encryption** – AES-GCM when available, otherwise AES-CBC with HMAC-SHA256, all with per-secret PBKDF2-derived keys
- **Centralized Storage** – Organized `bin`, `secrets`, and `certs` folders at an OS-aware default path
- **Certificate Automation** – Create self-signed certificates with SAN/EKU support, mandatory PFX protection, and optional PEM export
- **Certificate Store Integration** – Keep certificates in Windows certificate store without exporting files
- **Flexible Access** – Both name-based and direct path access patterns
- **PowerShell 5.1 & 7+ Compatible** – Works across all modern PowerShell versions
- **Safety First** – Atomic writes, zeroized secrets, ShouldProcess support, and redacted error messages

## PowerShell Version Compatibility

| Feature | PowerShell 5.1 | PowerShell 7+ |
|---------|---------------|---------------|
| Secret Management | ✅ Full Support | ✅ Full Support |
| PFX Certificate Export | ✅ Full Support | ✅ Full Support |
| PEM Certificate Export | ⚠️ Certificate Only | ✅ Full (with private key) |
| Certificate Store Mode | ✅ Full Support | ✅ Full Support |
| AES-GCM Encryption | ❌ AES-CBC fallback | ✅ Full Support |

**Note**: PowerShell 5.1 exports PEM files with certificate only (no private key). Use PFX files for full functionality or convert with OpenSSL. PowerShell 7+ exports complete PEM files with private keys.

## Default Locations

SecureStore selects a platform-specific default base folder. Override anytime with `-FolderPath`.

| Platform | Default Path |
|----------|--------------|
| Windows  | `C:\SecureStore` |
| Non-Windows | `Join-Path $HOME '.securestore'` |

> **Migration note:** Existing `secret` folders are still accepted but deprecated; migrate to `secrets` soon. Future major versions will remove `secret` support.

## Quick Start

```powershell
# Import the module
Import-Module SecureStore

# Inspect the environment at the default path
Test-SecureStoreEnvironment

# Store and retrieve your first secret
New-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' -Password 'P@ssw0rd!'
$password = Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret'

# Generate a certificate with PFX and PEM export
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -ExportPem

# Create a certificate in Windows certificate store only (no files)
New-SecureStoreCertificate -CertificateName 'MyAppCert' -Password 'CertPass123' -StoreOnly

# List all stored assets
Get-SecureStoreList | Format-List
```

## Installation

### Manual Installation
1. Download the latest release or clone this repository.
2. Copy the files to your module path, e.g. `C:\Program Files\WindowsPowerShell\Modules\SecureStore\` or `$HOME/.local/share/powershell/Modules/SecureStore`.
3. Import the module: `Import-Module SecureStore`.
4. Verify installation: `Test-SecureStoreEnvironment`.

### Zip Creator
1. Run the included `Create-SecureStoreZip.ps1` script.
2. Extract `SecureStore.zip` to a module directory.
3. Import and test as above.

## Folder Structure

SecureStore maintains a consistent structure for keys, encrypted secrets, and certificates.

```
<SecureStore base>
├── bin\                    # AES master keys (.bin files)
│   ├── Database.bin
│   ├── API.bin
│   └── MyApp.bin
├── secrets\                # Encrypted secrets (any filename)
│   ├── prod.secret
│   ├── api-key.secret
│   └── config.secret
└── certs\                  # Certificates (.pfx and .pem files)
    ├── MyApp.pfx
    ├── MyApp.pem           # PowerShell 7+: Full PEM with private key
    ├── WebServer.pfx       # PowerShell 5.1: Certificate-only PEM
    └── WebServer.pem
```

Use `-FolderPath` to target alternate roots:

```powershell
New-SecureStoreSecret -KeyName 'API' -SecretFileName 'token.secret' -Password 'PlainText' -FolderPath '/srv/app/secrets'
Get-SecureStoreList   -FolderPath '/srv/app/secrets'
```

## Function Reference

### `New-SecureStoreSecret`
Creates an encrypted secret using authenticated AES-256 encryption and atomic file writes.

```powershell
New-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' -Password 'P@ssw0rd!'
$secure = Read-Host 'Enter API token' -AsSecureString
New-SecureStoreSecret -KeyName 'Api' -SecretFileName 'token.secret' -Password $secure -Confirm:$false
```

### `Get-SecureStoreSecret`
Retrieves and decrypts stored secrets as plain text or credentials.

```powershell
Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret'
Get-SecureStoreSecret -KeyPath './bin/Api.bin' -SecretPath './secrets/api.secret' -AsCredential -UserName 'api-user'
```

### `New-SecureStoreCertificate`
Generates self-signed certificates with RSA 3072 or ECDSA curves, SAN/EKU support, and flexible export options.

#### Certificate Export Modes

**1. PFX Only (Default)**
```powershell
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!'
# Creates: WebApp.pfx (contains certificate + private key)
```

**2. PFX + PEM Export**
```powershell
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -ExportPem
# Creates: WebApp.pfx + WebApp.pem
# PowerShell 7+: PEM includes private key
# PowerShell 5.1: PEM includes certificate only (use PFX for private key)
```

**3. Certificate Store Only**
```powershell
New-SecureStoreCertificate -CertificateName 'MyAppCert' -Password 'CertPass123' -StoreOnly
# Certificate stored in Cert:\CurrentUser\My
# No files exported
```

#### Advanced Examples

```powershell
# ECDSA certificate
$secure = Read-Host 'PFX password' -AsSecureString
New-SecureStoreCertificate -CertificateName 'Api' -Password $secure -Algorithm ECDSA -CurveName nistP256 -ValidityYears 2 -ExportPem

# Advanced RSA certificate with SAN and EKU
New-SecureStoreCertificate -CertificateName 'WebServer' -Password 'Pass123' `
    -Algorithm RSA -KeyLength 4096 `
    -DnsName 'web.local', '*.web.local' `
    -IpAddress '10.0.1.100' `
    -EnhancedKeyUsage '1.3.6.1.5.5.7.3.1' `
    -ValidityYears 5 `
    -ExportPem

# Certificate for Windows authentication (store only)
New-SecureStoreCertificate -CertificateName 'UserAuth' -Password 'AuthPass123' `
    -EnhancedKeyUsage '1.3.6.1.5.5.7.3.2' `
    -StoreOnly
```

#### Certificate Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `CertificateName` | String | (Required) | Logical name for certificate files or friendly name |
| `Password` | String/SecureString | (Required) | Password protecting the PFX export |
| `FolderPath` | String | Platform default | Base SecureStore path |
| `ValidityYears` | Int | `1` | Certificate validity period (1-50 years) |
| `Subject` | String | `CN=<CertificateName>` | X.500 subject name |
| `Algorithm` | String | `RSA` | Key algorithm: `RSA` or `ECDSA` |
| `KeyLength` | Int | `3072` | RSA key size in bits (256-8192) |
| `CurveName` | String | `nistP256` | ECDSA curve: `nistP256`, `nistP384`, `nistP521` |
| `DnsName` | String[] | (None) | DNS subject alternative names |
| `IpAddress` | String[] | (None) | IP subject alternative names |
| `Email` | String[] | (None) | Email subject alternative names |
| `Uri` | String[] | (None) | URI subject alternative names |
| `EnhancedKeyUsage` | String[] | `1.3.6.1.5.5.7.3.1` | EKU OIDs (Server Authentication by default) |
| `ExportPem` | Switch | `$false` | Export PEM file alongside PFX |
| `StoreOnly` | Switch | `$false` | Keep in cert store without exporting files |

#### Common EKU OIDs

- `1.3.6.1.5.5.7.3.1` - Server Authentication (TLS/SSL servers)
- `1.3.6.1.5.5.7.3.2` - Client Authentication (TLS/SSL clients)
- `1.3.6.1.5.5.7.3.3` - Code Signing
- `1.3.6.1.5.5.7.3.4` - Email Protection
- `1.3.6.1.5.5.7.3.8` - Time Stamping

### `Get-SecureStoreList`
Summarizes stored keys, secrets, and certificates, warning about near-expiry certificates.

```powershell
Get-SecureStoreList
Get-SecureStoreList -FolderPath '/srv/app/secrets' -ExpiryWarningDays 45
```

### `Test-SecureStoreEnvironment`
Validates directory synchronization and folder readiness.

```powershell
Test-SecureStoreEnvironment
Test-SecureStoreEnvironment -FolderPath '/srv/app/secrets'
```

## PEM Export Formats

### PowerShell 7+ (Full PEM with Private Key)

**RSA Certificates:**
```
-----BEGIN CERTIFICATE-----
[Base64-encoded certificate]
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
[Base64-encoded private key]
-----END RSA PRIVATE KEY-----
```

**ECDSA Certificates:**
```
-----BEGIN CERTIFICATE-----
[Base64-encoded certificate]
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
[Base64-encoded private key]
-----END EC PRIVATE KEY-----
```

### PowerShell 5.1 (Certificate Only)

```
-----BEGIN CERTIFICATE-----
[Base64-encoded certificate]
-----END CERTIFICATE-----
```

**Note**: PowerShell 5.1 PEM files contain only the certificate. For deployments requiring private keys:
- Use the PFX file (contains certificate + private key)
- Convert PFX to PEM using OpenSSL: `openssl pkcs12 -in cert.pfx -out cert.pem -nodes`
- Use PowerShell 7+ for direct PEM export with private keys

## Usage Scenarios

### Database Connection
```powershell
New-SecureStoreSecret -KeyName 'ProdDB' -SecretFileName 'connection.secret' -Password (Read-Host 'DB Password' -AsSecureString)
$connectionSecret = Get-SecureStoreSecret -KeyName 'ProdDB' -SecretFileName 'connection.secret'
$connectionString = "Server=prod;Database=myapp;User=admin;Password=$connectionSecret;Encrypt=true"
```

### API Authentication
```powershell
New-SecureStoreSecret -KeyName 'OpenAI' -SecretFileName 'api-key.secret' -Password 'sk-1234567890abcdef'
$apiKey = Get-SecureStoreSecret -KeyName 'OpenAI' -SecretFileName 'api-key.secret'
$headers = @{ Authorization = "Bearer $apiKey" }
Invoke-RestMethod -Uri 'https://api.openai.com/v1/models' -Headers $headers
```

### Remote PowerShell
```powershell
New-SecureStoreSecret -KeyName 'ServerAdmin' -SecretFileName 'admin.secret' -Password (Read-Host 'Admin Password' -AsSecureString)
$adminCred = Get-SecureStoreSecret -KeyName 'ServerAdmin' -SecretFileName 'admin.secret' -AsCredential -UserName 'admin'
Invoke-Command -ComputerName 'server01' -Credential $adminCred -ScriptBlock {
    Get-Service | Where-Object Status -eq 'Stopped'
}
```

### Certificates for Windows Authentication
```powershell
# Create certificate in Windows certificate store for authentication
New-SecureStoreCertificate -CertificateName 'UserAuth' -Password 'AuthPass123' `
    -Subject 'CN=John Doe, O=MyCompany' `
    -EnhancedKeyUsage '1.3.6.1.5.5.7.3.2' `
    -StoreOnly

# Certificate is now available in Cert:\CurrentUser\My for Windows authentication
```

### Certificates for HTTPS (Windows)
```powershell
# Create certificate with PEM for web server
New-SecureStoreCertificate -CertificateName 'WebApp' -Password (Read-Host 'PFX password' -AsSecureString) `
    -Subject 'CN=myapp.local' `
    -DnsName 'myapp.local', '*.myapp.local' `
    -ExportPem

# Import PFX to Windows certificate store
$certPath = Join-Path (Get-SecureStoreList).BasePath 'certs/WebApp.pfx'
$certPassword = Read-Host 'PFX password' -AsSecureString
Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\My -Password $certPassword
```

### Certificates for Linux/Docker Deployment (PowerShell 7+)
```powershell
# Create certificate for containerized application (PowerShell 7+ for full PEM)
New-SecureStoreCertificate -CertificateName 'ApiServer' -Password 'PfxPass123' `
    -DnsName 'api.company.com' `
    -Algorithm ECDSA -CurveName nistP384 `
    -ExportPem

# Copy PEM to deployment location (includes both cert and private key on PS7+)
$pemPath = Join-Path (Get-SecureStoreList).BasePath 'certs/ApiServer.pem'
Copy-Item $pemPath -Destination '/srv/docker/ssl/api-server.pem'
```

### Nginx Configuration with SecureStore PEM
```nginx
server {
    listen 443 ssl;
    server_name api.company.com;
    
    # PowerShell 7+: Use PEM file with both cert and key
    ssl_certificate /srv/docker/ssl/api-server.pem;
    ssl_certificate_key /srv/docker/ssl/api-server.pem;
    
    # PowerShell 5.1: Convert PFX to PEM with OpenSSL first
    # openssl pkcs12 -in api-server.pfx -out api-server.pem -nodes
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
}
```

## Security Features

- **Authenticated Encryption**: AES-256-GCM (or AES-256-CBC + HMAC-SHA256 on down-level hosts) with per-secret nonces and integrity checks
- **Key Derivation**: PBKDF2-SHA256 with 200k iterations and random salt for each secret
- **Secure Secret Handling**: SecureString conversion, BSTR zeroization, and credential-safe output
- **Safe Storage**: Atomic file writes via temporary files and forced flush before rename
- **Cross-Platform Defaults**: OS-aware storage locations with optional overrides
- **ShouldProcess Support**: `-WhatIf`/`-Confirm` available on mutating commands
- **Certificate Security**: 
  - RSA: 3072-bit keys by default (configurable up to 8192-bit)
  - ECDSA: P-256 curve by default (P-384 and P-521 available)
  - SHA-256 signatures
  - Mandatory PFX passwords
  - Flexible export options (files or store only)
  - SAN/EKU support for modern certificate requirements
- **Memory Safety**: All sensitive buffers (keys, passwords, certificates) are zeroed after use
- **Certificate Expiry Warnings**: Proactive alerts for certificates nearing expiration

## Enterprise Features

- **Team Friendly**: Predictable folder structure simplifies onboarding and backups
- **Automation Ready**: Built for CI/CD pipelines with `-Confirm:$false` support
- **Audit Friendly**: File-system logging and sanitized error output help investigations
- **Scalable**: Supports unlimited keys, secrets, and certificates without cloud dependencies
- **Deployment Flexibility**: Export certificates as files or keep in Windows certificate store
- **PowerShell 5.1 & 7+ Compatible**: Works across all modern PowerShell versions

## Requirements

- **PowerShell**: 5.1 or later (Windows PowerShell or PowerShell Core/7+)
- **Operating System**: Windows (uses Windows certificate APIs)
- **.NET Framework**: 4.5+ for PowerShell 5.1, .NET Core 3.1+ for PowerShell 7+

## Testing

Run the included test suite to verify functionality:

```powershell
.\tests\Test-SecureStoreModule.ps1
```

The test suite automatically detects your PowerShell version and adjusts expectations accordingly.

## Best Practices

### Secrets Management
1. **Organize by Application**: Use descriptive `KeyName` values like "MyApp", "Database", "API"
2. **Descriptive Filenames**: Use clear `SecretFileName` like "prod.secret", "api-key.secret"
3. **Key Reuse**: One key can encrypt multiple secrets - reuse `KeyName` for related secrets
4. **Regular Rotation**: Periodically create new secrets and retire old ones

### Certificate Management

#### Export Mode Selection
- **PFX Only**: For Windows-only deployments where certificates stay in Windows certificate stores
- **PFX + PEM**: For cross-platform deployments (Linux, Docker, Kubernetes)
- **Store Only**: For Windows authentication, code signing, or when certificates don't need file export

#### PowerShell Version Considerations
- **PowerShell 7+**: Recommended for full PEM export with private keys
- **PowerShell 5.1**: Use PFX files for deployments or convert with OpenSSL

#### General Certificate Practices
1. **Choose Algorithm Wisely**: 
   - RSA: Better compatibility, larger keys/signatures, use for legacy system support
   - ECDSA: Smaller, faster, modern (preferred for new deployments)
2. **Key Sizes**: 
   - RSA: 3072-bit minimum (default), 4096-bit for high security
   - ECDSA: P-256 for standard, P-384 for high security, P-521 for maximum security
3. **Subject Alternative Names**: Always include all DNS names and IPs your service will use
4. **Enhanced Key Usage**: Specify appropriate EKUs for your certificate's purpose
5. **Strong Passwords**: Use strong passwords for PFX file protection
6. **Validity Periods**: Balance security (shorter) vs maintenance (longer) - 1-2 years recommended
7. **Backup Strategy**: Include entire `certs\` folder in your backup strategy

### General
1. **Backup Strategy**: Regularly backup the entire SecureStore folder
2. **Access Control**: Use file system permissions to restrict folder access
3. **Test Environment**: Use `Test-SecureStoreEnvironment` to verify setup before deployment

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Join conversations in GitHub Discussions
- **Documentation**: Full documentation available in the repository

## Roadmap

- [x] PowerShell 5.1+ support
- [x] RSA and ECDSA certificate generation
- [x] Subject Alternative Names (SAN)
- [x] Enhanced Key Usage (EKU)
- [x] PEM export (full in PS7+, certificate-only in PS5.1)
- [x] Certificate store-only mode
- [x] Authenticated AES-256 encryption
- [ ] Certificate-based secret encryption/decryption
- [ ] PowerShell Gallery publication
- [ ] Linux/macOS native certificate generation
- [ ] Import/export utilities for migration
- [ ] GUI management interface

---

**Star this repository if SecureStore helped you secure your PowerShell environment!**

**Made with care for the PowerShell community**