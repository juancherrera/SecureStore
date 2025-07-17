# SecureStore

> Enterprise-grade PowerShell module for secure local secret management and certificate generation

SecureStore provides a centralized, secure solution for managing passwords, API keys, and certificates in PowerShell environments. With AES-256 encryption and organized folder structure, it's perfect for DevOps workflows, automation scripts, and enterprise environments.

## Key Features

- **AES-256 Encryption** - Industry-standard security for all stored secrets
- **Centralized Storage** - Organized `C:\SecureStore` structure with `bin\`, `secret\`, and `certs\` folders
- **Certificate Generation** - Create self-signed certificates with PFX and PEM export
- **Flexible Access** - Both name-based and direct path access methods
- **No Cloud Dependencies** - Purely local storage with Windows file system permissions
- **Enterprise Ready** - Built for team environments and automation workflows
- **PowerShell 5.1+** - Compatible with Windows PowerShell and PowerShell Core

## Quick Start

```powershell
# Import the module
Import-Module SecureStore

# Test your environment
Test-SecureStoreEnvironment

# Create your first secret
New-SecureStoreSecret -KeyName "Database" -SecretFileName "prod.secret" -Password "MySecurePassword123"

# Retrieve the secret
$password = Get-SecureStoreSecret -KeyName "Database" -SecretFileName "prod.secret"

# Create a certificate
New-SecureStoreCertificate -CertificateName "MyApp" -Password "CertPassword123"

# List all your assets
Get-SecureStoreList
```

## Installation

### Method 1: Manual Installation
1. Download the latest release or clone this repository
2. Extract/copy all files to: `C:\Program Files\WindowsPowerShell\Modules\SecureStore\`
3. Import the module: `Import-Module SecureStore`
4. Verify installation: `Test-SecureStoreEnvironment`

### Method 2: Using the Zip Creator
1. Run the included `Create-SecureStoreZip.ps1` script
2. Extract `SecureStore.zip` to your PowerShell modules directory
3. Import and test as above

## Folder Structure

SecureStore creates a standardized folder structure for all your security assets:

```
C:\SecureStore\
├── bin\                    # AES encryption keys (.bin files)
│   ├── Database.bin
│   ├── API.bin
│   └── MyApp.bin
├── secrets\                 # Encrypted secrets (any filename)
│   ├── prod.secret
│   ├── api-key.secret
│   └── config.secret
└── certs\                  # Certificates (.pfx and .pem files)
    ├── MyApp.pfx
    ├── MyApp.pem
    ├── WebServer.pfx
    └── WebServer.pem
```

## Functions Reference

### `New-SecureStoreSecret`
Creates an encrypted secret with a local encryption key.

```powershell
# Basic usage (creates in C:\SecureStore)
New-SecureStoreSecret -KeyName "MyApp" -SecretFileName "database.secret" -Password "MyPassword123"

# Custom location
New-SecureStoreSecret -KeyName "API" -SecretFileName "token.secret" -Password "api-token-xyz" -FolderPath "D:\MySecrets"
```

### `Get-SecureStoreSecret`
Retrieves and decrypts a stored secret.

```powershell
# Get as plain text
$password = Get-SecureStoreSecret -KeyName "MyApp" -SecretFileName "database.secret"

# Get as PSCredential object
$cred = Get-SecureStoreSecret -KeyName "MyApp" -SecretFileName "database.secret" -AsCredential

# Direct path access
$password = Get-SecureStoreSecret -KeyPath ".\bin\MyApp.bin" -SecretPath ".\secret\database.secret"
```

### `New-SecureStoreCertificate`
Creates self-signed certificates with PFX and PEM export.

```powershell
# Basic certificate (2-year validity)
New-SecureStoreCertificate -CertificateName "MyApp" -Password "CertPass123"

# Custom validity and subject
New-SecureStoreCertificate -CertificateName "WebServer" -Password "Pass123" -ValidityYears 5 -Subject "CN=myapp.local, O=My Company"
```

### `Get-SecureStoreList`
Lists all available secrets and certificates.

```powershell
# List default location
Get-SecureStoreList

# List custom location
Get-SecureStoreList -FolderPath "D:\MySecrets"
```

### `Test-SecureStoreEnvironment`
Tests environment and validates folder structure.

```powershell
# Test default location
Test-SecureStoreEnvironment

# Test custom location  
Test-SecureStoreEnvironment -FolderPath "D:\MySecrets"
```

## Usage Examples

### Database Connection
```powershell
# Store database password
New-SecureStoreSecret -KeyName "ProdDB" -SecretFileName "connection.secret" -Password "MyDbPassword123"

# Use in connection string
$dbPassword = Get-SecureStoreSecret -KeyName "ProdDB" -SecretFileName "connection.secret"
$connectionString = "Server=prod-server;Database=myapp;User=admin;Password=$dbPassword;Encrypt=true"
```

### API Authentication
```powershell
# Store API key
New-SecureStoreSecret -KeyName "OpenAI" -SecretFileName "api-key.secret" -Password "sk-1234567890abcdef"

# Use in REST calls
$apiKey = Get-SecureStoreSecret -KeyName "OpenAI" -SecretFileName "api-key.secret"
$headers = @{ "Authorization" = "Bearer $apiKey" }
Invoke-RestMethod -Uri "https://api.openai.com/v1/models" -Headers $headers
```

### Remote PowerShell
```powershell
# Store admin credentials
New-SecureStoreSecret -KeyName "ServerAdmin" -SecretFileName "admin.secret" -Password "AdminPassword123"

# Use for remote sessions
$adminCred = Get-SecureStoreSecret -KeyName "ServerAdmin" -SecretFileName "admin.secret" -AsCredential
Invoke-Command -ComputerName "server01" -Credential $adminCred -ScriptBlock {
    Get-Service | Where-Object Status -eq "Stopped"
}
```

### Certificate for HTTPS
```powershell
# Create certificate for web application
New-SecureStoreCertificate -CertificateName "WebApp" -Password "CertPass123" -Subject "CN=myapp.local"

# Import to IIS (requires Administrator)
$certPath = "C:\SecureStore\certs\WebApp.pfx"
$certPassword = ConvertTo-SecureString "CertPass123" -AsPlainText -Force
Import-PfxCertificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\My -Password $certPassword
```

## Security Features

- **AES-256 Encryption**: Uses PowerShell's built-in `ConvertFrom-SecureString` with 256-bit keys
- **Cryptographically Secure Keys**: Generated using `RNGCryptoServiceProvider`
- **Memory Safety**: Proper cleanup of sensitive data using BSTR marshaling
- **File System Permissions**: Leverages Windows ACLs for access control
- **No Network Dependencies**: Everything stored locally with no cloud exposure
- **Certificate Security**: 2048-bit RSA keys with SHA-256 signatures

## Enterprise Features

- **Team Environments**: Consistent folder structure across team members
- **Backup-Friendly**: Single folder contains all security assets
- **Automation Ready**: Perfect for CI/CD pipelines and scheduled tasks
- **Audit Trail**: File system logs provide access tracking
- **Scalable**: Supports unlimited keys, secrets, and certificates
- **Version Control Safe**: Binary keys and encrypted secrets don't expose plaintext

## Requirements

- **PowerShell**: 5.1 or later (Windows PowerShell or PowerShell Core)
- **Operating System**: Windows (uses Windows certificate store for cert generation)
- **Permissions**: Write access to `C:\SecureStore` (or custom folder)
- **.NET Framework**: 4.5+ (typically already installed)

## Best Practices

1. **Organize by Application**: Use descriptive `KeyName` values like "MyApp", "Database", "API"
2. **Descriptive Filenames**: Use clear `SecretFileName` like "prod.secret", "api-key.secret"
3. **Key Reuse**: One key can encrypt multiple secrets - reuse `KeyName` for related secrets
4. **Backup Strategy**: Regularly backup the entire `C:\SecureStore` folder
5. **Access Control**: Use Windows file permissions to restrict folder access
6. **Certificate Passwords**: Use strong passwords for certificate protection
7. **Regular Rotation**: Periodically create new secrets and retire old ones

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
1. Fork this repository
2. Clone your fork: `git clone https://github.com/yourusername/SecureStore-PowerShell.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes and test thoroughly
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/yourusername/SecureStore-PowerShell/issues)
- **Discussions**: Join conversations in [GitHub Discussions](https://github.com/yourusername/SecureStore-PowerShell/discussions)
- **Documentation**: Full documentation available in the repository

## Roadmap

- [ ] PowerShell Gallery publication
- [ ] Linux/macOS support (certificate generation)
- [ ] Import/export utilities for migration
- [ ] Advanced key derivation options
- [ ] Integration with Azure Key Vault (optional)
- [ ] GUI management interface

## Project Stats

![GitHub stars](https://img.shields.io/github/stars/yourusername/SecureStore-PowerShell?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/SecureStore-PowerShell?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/yourusername/SecureStore-PowerShell?style=social)

---

**Star this repository if SecureStore helped you secure your PowerShell environment!**

**Made with care for the PowerShell community**