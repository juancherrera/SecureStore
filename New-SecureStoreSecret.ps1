<#
.SYNOPSIS
Creates or updates an encrypted secret in the SecureStore repository.

.DESCRIPTION
New‑SecureStoreSecret derives or reuses an encryption key and protects the supplied
secret using authenticated AES‑256 encryption (version 2) or, when certificate
parameters are supplied, encrypts using an RSA public key from a certificate
(version 3).  The cmdlet writes payloads using atomic file operations and honours
ShouldProcess semantics for safe updates.

.PARAMETER KeyName
Logical name used to store the master encryption key (.bin file).  Required for
AES‑based secrets.

.PARAMETER SecretFileName
Name of the encrypted payload file stored beneath the secrets directory.

.PARAMETER Password
Secret value to protect.  Accepts plain text or SecureString; converted securely.

.PARAMETER FolderPath
Optional custom SecureStore base path.  Defaults to the platform-specific root.

.PARAMETER CertificateThumbprint
Encrypts the secret using the public key of the certificate identified by this
thumbprint in the CurrentUser or LocalMachine certificate store.  When present,
-KeyName is ignored and the secret is stored as a version 3 payload.

.PARAMETER CertificatePath
Encrypts the secret using the public key from a PFX file at this path.  Requires
-CertificatePassword.  When present, -KeyName is ignored and the secret is
stored as a version 3 payload.

.PARAMETER CertificatePassword
Password used to open the PFX file specified by -CertificatePath.  Accepts a
plain string or SecureString.

.INPUTS
System.String, System.Security.SecureString.  Accepts pipeline input for -Password.

.OUTPUTS
None.  Writes files and emits verbose information.

.EXAMPLE
New-SecureStoreSecret -KeyName 'Api' -SecretFileName 'token.secret' -Password 'abcd1234'

Creates or updates token.secret using AES encryption (version 2).

.EXAMPLE
New-SecureStoreSecret -SecretFileName 'cert.secret' -Password 'secret' `
  -CertificateThumbprint 'ABCDEF1234...' -FolderPath 'C:\SecureStore'

Encrypts secret with the specified certificate (version 3).
#>
function New-SecureStoreSecret {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByKey')]
  param(
    [Parameter(ParameterSetName = 'ByKey', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyName,

    [Parameter(ParameterSetName = 'ByKey', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretFileName,

    [Parameter(ParameterSetName = 'ByKey', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertThumbprint', Mandatory = $true)]
    [Parameter(ParameterSetName = 'ByCertPath', Mandatory = $true)]
    [ValidateNotNull()]
    [object]$Password,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$FolderPath = $script:DefaultSecureStorePath,

    [Parameter(ParameterSetName = 'ByCertThumbprint')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'ByCertPath')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificatePath,

    [Parameter(ParameterSetName = 'ByCertPath')]
    [ValidateNotNull()]
    [object]$CertificatePassword
  )

  begin {
    # Ensure helper function is in scope
    if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
      . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
    }
  }

  process {
    $securePassword = $null
    $plaintextBytes = $null
    try {
      # Convert password input to SecureString
      $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
      $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

      # AES‑based secret creation (version 2)
      if ($PSCmdlet.ParameterSetName -eq 'ByKey') {
        # Resolve key and secret paths
        if (Test-SecureStorePathLike -Value $KeyName) {
          $keyFilePath = Resolve-SecureStorePath -Path $KeyName -BasePath $paths.BasePath
        }
        else {
          $keyChild = if ($KeyName.EndsWith('.bin', [System.StringComparison]::OrdinalIgnoreCase)) { $KeyName } else { "$KeyName.bin" }
          $keyFilePath = Join-Path -Path $paths.BinPath -ChildPath $keyChild
        }

        $secretInputPath = if (Test-SecureStorePathLike -Value $SecretFileName) {
          Resolve-SecureStorePath -Path $SecretFileName -BasePath $paths.BasePath
        }
        else {
          Join-Path -Path $paths.SecretPath -ChildPath $SecretFileName
        }
        $secretFilePath = ConvertTo-SecureStorePreferredSecretPath -Path $secretInputPath -PreferredSecretDir $paths.SecretPath -LegacySecretDir $paths.LegacySecretPath

        if (-not $PSCmdlet.ShouldProcess($secretFilePath, "Create or update secure secret")) {
          return
        }

        # Load or create master key
        $encryptionKey = $null
        $keyCreated = $false
        if (-not (Test-Path -LiteralPath $keyFilePath)) {
          $encryptionKey = New-Object byte[] 32
          $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
          try {
            $rng.GetBytes($encryptionKey)
          }
          finally {
            $rng.Dispose()
          }
          Write-SecureStoreFile -Path $keyFilePath -Bytes $encryptionKey
          $keyCreated = $true
        }
        if (-not $encryptionKey) {
          $encryptionKey = Read-SecureStoreByteArray -Path $keyFilePath
        }

        # Encrypt plaintext with AES and write JSON payload
        try {
          $plaintextBytes = Get-SecureStorePlaintextData -SecureString $securePassword
          $payloadJson = Protect-SecureStoreSecret -Plaintext $plaintextBytes -MasterKey $encryptionKey
          $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
          try {
            Write-SecureStoreFile -Path $secretFilePath -Bytes $payloadBytes
          }
          finally {
            [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
          }
        }
        finally {
          if ($null -ne $plaintextBytes) {
            [Array]::Clear($plaintextBytes, 0, $plaintextBytes.Length)
          }
          if ($null -ne $encryptionKey) {
            [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
          }
        }

        if ($keyCreated) {
          Write-Verbose "Encryption key '$KeyName' stored at '$keyFilePath'."
        }
      }
      else {
        # Certificate‑based secret creation (version 3)
        # Determine output path; KeyName is ignored
        $secretInputPath = if (Test-SecureStorePathLike -Value $SecretFileName) {
          Resolve-SecureStorePath -Path $SecretFileName -BasePath $paths.BasePath
        }
        else {
          Join-Path -Path $paths.SecretPath -ChildPath $SecretFileName
        }
        $secretFilePath = ConvertTo-SecureStorePreferredSecretPath -Path $secretInputPath -PreferredSecretDir $paths.SecretPath -LegacySecretDir $paths.LegacySecretPath

        if (-not $PSCmdlet.ShouldProcess($secretFilePath, "Create or update certificate‑encrypted secret")) {
          return
        }

        # Ensure certificate helper functions are available
        if (-not (Get-Command -Name 'Protect-SecureStoreSecretWithCertificate' -ErrorAction SilentlyContinue)) {
          . "$PSScriptRoot/Get-SecureStoreCertificateForEncryption.ps1"
        }

        # Acquire certificate (from thumbprint or PFX)
        $cert = $null
        if ($PSCmdlet.ParameterSetName -eq 'ByCertPath') {
          $certPw = $CertificatePassword
          if ($certPw -is [System.Security.SecureString]) {
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($certPw)
            try {
              $certPw = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            }
            finally {
              [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
          }
          $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $CertificatePath,
            $certPw,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
          )
        }
        else {
          # Search in CurrentUser and LocalMachine stores
          $thumbUpper = $CertificateThumbprint.Replace(' ', '').ToUpperInvariant()
          $store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'My', 'CurrentUser'
          $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
          try {
            $cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbUpper } | Select-Object -First 1
          }
          finally {
            $store.Close()
          }
          if (-not $cert) {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store 'My', 'LocalMachine'
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            try {
              $cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbUpper } | Select-Object -First 1
            }
            finally {
              $store.Close()
            }
          }
          if (-not $cert) {
            throw [System.IO.FileNotFoundException]::new("Could not locate certificate with thumbprint $CertificateThumbprint.")
          }
        }

        try {
          $plaintextBytes = Get-SecureStorePlaintextData -SecureString $securePassword
          $payloadJson = Protect-SecureStoreSecretWithCertificate -Plaintext $plaintextBytes -Certificate $cert
          $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
          try {
            Write-SecureStoreFile -Path $secretFilePath -Bytes $payloadBytes
          }
          finally {
            [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
          }
        }
        finally {
          if ($plaintextBytes) { [Array]::Clear($plaintextBytes, 0, $plaintextBytes.Length) }
          if ($cert) { $cert.Dispose() }
        }
      }
    }
    catch {
      throw [System.InvalidOperationException]::new("Failed to create or update secret '$SecretFileName'.", $_.Exception)
    }
    finally {
      if ($securePassword) {
        $securePassword.Dispose()
      }
    }
  }
}
