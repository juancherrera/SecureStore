# SecureStore

> Enterprise-grade PowerShell module for secure local secret management and certificate generation

SecureStore provides a centralized, secure solution for managing passwords, API keys, and certificates across Windows and cross-platform PowerShell environments. With authenticated AES-256 encryption, safe file handling, and an organized folder structure, it is well suited for DevOps workflows, automation scripts, and enterprise deployments.

## Key Features

- **AES-256 Authenticated Encryption** – AES-GCM when available, otherwise AES-CBC with HMAC-SHA256, all with per-secret PBKDF2-derived keys
- **Centralized Storage** – Organized `bin`, `secrets`, and `certs` folders at an OS-aware default path
- **Certificate Automation** – Create self-signed certificates with SAN/EKU support, mandatory PFX protection, and optional PEM export
- **Flexible Access** – Both name-based and direct path access patterns
- **Safety First** – Atomic writes, zeroized secrets, ShouldProcess support, and redacted error messages
- **PowerShell 5.1+** – Compatible with Windows PowerShell and PowerShell 7+

## Default Locations

SecureStore selects a platform-specific default base folder. Override anytime with `-FolderPath`.

| Platform | Default Path |
|----------|--------------|
| Windows  | `Join-Path $env:ProgramData 'SecureStore'` |
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

# Generate a certificate with SAN support
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -ExportPem

# List all stored assets
Get-SecureStoreList | Format-List
```

> **Cross-platform note:** On Windows, SecureStore defaults to `C:\ProgramData\SecureStore`. On Linux and macOS it uses `$HOME/.securestore`. Override with `-FolderPath` to target alternate roots.

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
└── certs\                  # Certificates (.pfx, optional .pem)
    ├── MyApp.pfx
    ├── MyApp.pem
    ├── WebServer.pfx
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
Generates self-signed certificates with RSA 3072 or ECDSA curves, SAN/EKU support, and secure exports.

```powershell
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -ExportPem
$secure = Read-Host 'PFX password' -AsSecureString
New-SecureStoreCertificate -CertificateName 'Api' -Password $secure -Algorithm ECDSA -CurveName nistP256 -ValidityYears 2
```

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

### Certificates for HTTPS
```powershell
New-SecureStoreCertificate -CertificateName 'WebApp' -Password (Read-Host 'PFX password' -AsSecureString) -Subject 'CN=myapp.local'
$certPath = (Join-Path (Get-SecureStoreList).BasePath 'certs/WebApp.pfx')
Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host 'PFX password' -AsSecureString)
```

## Security Features

- **Authenticated Encryption**: AES-256-GCM (or AES-256-CBC + HMAC-SHA256 on down-level hosts) with per-secret nonces and integrity checks
- **Key Derivation**: PBKDF2-SHA256 with 200k iterations and random salt for each secret
- **Secure Secret Handling**: SecureString conversion, BSTR zeroization, and credential-safe output
- **Safe Storage**: Atomic file writes via temporary files and forced flush before rename
- **Cross-Platform Defaults**: OS-aware storage locations with optional overrides
- **ShouldProcess Support**: `-WhatIf`/`-Confirm` available on mutating commands
- **Certificate Hygiene**: Mandatory PFX passwords, SAN/EKU support, and near-expiry warnings

## Enterprise Features

- **Team Friendly**: Predictable folder structure simplifies onboarding and backups
- **Automation Ready**: Built for CI/CD pipelines with strict mocks for testing
- **Audit Friendly**: File-system logging and sanitized error output help investigations
- **Scalable**: Supports unlimited keys, secrets, and certificates without cloud dependencies

## Requirements

- **PowerShell**: 5.1 or later (Windows PowerShell or PowerShell Core)
- **Certificates**: Windows certificate APIs are required for live certificate generation; tests use mocks

## Testing & Quality Gates

Run the included Pester tests and script analyzer before submitting changes:

```powershell
Invoke-ScriptAnalyzer -Path .\SecureStore.psm1
Invoke-Pester -Path .\tests -Output Detailed
```

