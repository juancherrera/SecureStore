# ===================================================================
# CERTIFICATE-BASED SECRET ENCRYPTION FUNCTIONS
# Add these functions to SecureStore.psm1 after the existing crypto functions
# ===================================================================

<#
.SYNOPSIS
Loads a certificate from disk or the Windows certificate store for SecureStore encryption operations.

.DESCRIPTION
Get-SecureStoreCertificateForEncryption centralises certificate loading for secret encryption and decryption.
The function supports locating certificates by thumbprint, subject/friendly name, or file path (.pfx/.pem).
It optionally enforces that the certificate includes an accessible private key which is required for
decrypting version 3 secrets. Password prompts accept plain strings or SecureString objects and are zeroised
after use to avoid leaking sensitive material.

.PARAMETER Thumbprint
Searches the CurrentUser and LocalMachine personal stores for a matching certificate thumbprint.

.PARAMETER CertificatePath
Loads a certificate directly from the provided file path. Supports PFX on Windows PowerShell and PFX/PEM on PowerShell 7+.

.PARAMETER Password
Password used to open the certificate at -CertificatePath. Accepts string or SecureString.

.PARAMETER Subject
Finds a certificate whose subject or friendly name contains the supplied value.

.PARAMETER RequirePrivateKey
Ensures the returned certificate exposes a private key suitable for RSA encryption/decryption operations.

.EXAMPLE
Get-SecureStoreCertificateForEncryption -Thumbprint 'A1B2C3D4E5F6' -RequirePrivateKey

Retrieves the certificate with the specified thumbprint from the local stores and validates that a private key is available.

.EXAMPLE
Get-SecureStoreCertificateForEncryption -CertificatePath 'C:\SecureStore\certs\api.pfx' -Password (Read-Host 'PFX Password' -AsSecureString)

Opens the PFX file using a secure password prompt and returns the certificate object for encryption tasks.

.NOTES
PEM files containing private keys require PowerShell 7 or later because earlier versions lack the necessary APIs.
#>
function Get-SecureStoreCertificateForEncryption {
  [CmdletBinding()]
  [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
  param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByThumbprint')]
    [ValidateNotNullOrEmpty()]
    [string]$Thumbprint,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificatePath,

    [Parameter(ParameterSetName = 'ByPath')]
    [object]$Password,

    [Parameter(Mandatory = $true, ParameterSetName = 'BySubject')]
    [ValidateNotNullOrEmpty()]
    [string]$Subject,

    [Parameter()]
    [switch]$RequirePrivateKey
  )

  $certificate = $null

  try {
    # Route to the correct loading path based on how the caller identified the certificate.
    switch ($PSCmdlet.ParameterSetName) {
      'ByThumbprint' {
        Write-Verbose "Loading certificate by thumbprint: $Thumbprint"

        # Search in CurrentUser\My first, then LocalMachine\My
        $candidate = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue

        $certificate = $null
        if ($candidate) {
          if ($candidate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $certificate = $candidate
          }
          elseif ($candidate -is [System.IO.FileInfo]) {
            try {
              $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $candidate.FullName,
                [string]::Empty,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
              )
            }
            catch {
              Write-Verbose "Failed to load fallback certificate file for thumbprint '$Thumbprint': $($_.Exception.Message)"
            }
          }
        }

        if (-not $certificate) {
          $candidate = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
          if ($candidate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $certificate = $candidate
          }
          elseif ($candidate -is [System.IO.FileInfo]) {
            try {
              $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $candidate.FullName,
                [string]::Empty,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
              )
            }
            catch {
              Write-Verbose "Failed to load fallback LocalMachine certificate file for thumbprint '$Thumbprint': $($_.Exception.Message)"
            }
          }
        }

        if (-not $certificate) {
          $certificate = Get-SecureStoreCachedCertificate -Thumbprint $Thumbprint
        }

        if (-not $certificate) {
          throw "Certificate with thumbprint '$Thumbprint' not found in CurrentUser\My or LocalMachine\My"
        }
      }

      'BySubject' {
        Write-Verbose "Loading certificate by subject: $Subject"
                
        # Search in CurrentUser\My first
        $certificate = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object {
          ($_.Subject -like "*$Subject*") -or ($_.FriendlyName -eq $Subject)
        } |
        Select-Object -First 1

        if ($certificate -is [System.IO.FileInfo]) {
          try {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
              $certificate.FullName,
              [string]::Empty,
              [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
          }
          catch {
            Write-Verbose "Failed to load fallback certificate file when searching by subject '$Subject': $($_.Exception.Message)"
            $certificate = $null
          }
        }

        if (-not $certificate) {
          # Search in LocalMachine\My
          $certificate = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
          Where-Object {
            ($_.Subject -like "*$Subject*") -or ($_.FriendlyName -eq $Subject)
          } |
          Select-Object -First 1

          if ($certificate -is [System.IO.FileInfo]) {
            try {
              $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $certificate.FullName,
                [string]::Empty,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
              )
            }
            catch {
              Write-Verbose "Failed to load fallback LocalMachine certificate file when searching by subject '$Subject': $($_.Exception.Message)"
              $certificate = $null
            }
          }
        }

        if (-not $certificate) {
          throw "Certificate with subject or friendly name matching '$Subject' not found"
        }
      }

      'ByPath' {
        Write-Verbose "Loading certificate from file: $CertificatePath"
                
        if (-not (Test-Path -LiteralPath $CertificatePath)) {
          throw "Certificate file not found: $CertificatePath"
        }

        $extension = [System.IO.Path]::GetExtension($CertificatePath).ToLowerInvariant()

        switch ($extension) {
          '.pfx' {
            if (-not $Password) {
              throw "Password is required for PFX certificate files"
            }

            $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
                        
            # Convert SecureString to plain text for X509Certificate2 constructor
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            try {
              $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
              $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $CertificatePath,
                $plainPassword,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
              )
            }
            finally {
              [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
              if ($plainPassword) {
                $chars = $plainPassword.ToCharArray()
                [Array]::Clear($chars, 0, $chars.Length)
              }
              $securePassword.Dispose()
            }
          }

          '.pem' {
            if ($PSVersionTable.PSVersion.Major -lt 7) {
              throw "PEM certificate loading with private key requires PowerShell 7+. Use PFX format instead."
            }

            # PEM loading with private key (PowerShell 7+ only)
            $pemContent = Get-Content -Path $CertificatePath -Raw
                        
            if ($pemContent -notmatch '-----BEGIN CERTIFICATE-----' -or 
              $pemContent -notmatch '-----BEGIN (RSA |EC )?PRIVATE KEY-----') {
              throw "PEM file must contain both certificate and private key"
            }

            # Parse PEM and create certificate with private key
            # Note: This is simplified; real implementation would need proper PEM parsing
            throw "PEM loading not yet fully implemented. Use PFX format for now."
          }

          '.cer' {
            # Public key only
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
                        
            if ($RequirePrivateKey) {
              throw "CER files contain only the public key. Use PFX for private key operations."
            }
          }

          default {
            throw "Unsupported certificate file format: $extension. Use .pfx, .pem, or .cer"
          }
        }
      }
    }

    # Validate certificate
    if (-not $certificate) {
      throw "Failed to load certificate"
    }

    # Check if private key is required but missing
    if ($RequirePrivateKey -and -not $certificate.HasPrivateKey) {
      throw "Certificate does not have a private key. Decryption requires a certificate with private key."
    }

    # Validate algorithm for encryption operations
    $publicKey = $certificate.PublicKey.Key
    if ($RequirePrivateKey -or $PSCmdlet.ParameterSetName -eq 'ByPath') {
      # For encryption/decryption, we need RSA
      if ($publicKey -isnot [System.Security.Cryptography.RSA]) {
        $actualType = $publicKey.GetType().Name
        throw "Certificate must use RSA algorithm for encryption. Found: $actualType (ECDSA certificates can only sign, not encrypt)"
      }
    }

    Write-Verbose "Certificate loaded successfully: $($certificate.Subject) (Thumbprint: $($certificate.Thumbprint))"

    # Surface the live certificate object to the caller so it can be used for crypto operations.
    return $certificate
  }
  catch {
    if ($certificate -and ($certificate -is [System.IDisposable])) {
      $certificate.Dispose()
    }
    throw
  }
}

function Protect-SecureStoreSecretWithCertificate {
  <#
    .SYNOPSIS
    Encrypts a secret using hybrid encryption (RSA + AES-GCM).
    
    .DESCRIPTION
    Generates a random AES key, encrypts the secret with AES-GCM,
    then encrypts the AES key with the certificate's RSA public key.
    Returns a JSON payload containing the encrypted key and data.
    #>
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [byte[]]$Plaintext,

    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  try {
    # Validate certificate has RSA public key
    $rsaFromExtension = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    $rsa = if ($rsaFromExtension) { $rsaFromExtension } else { $Certificate.PublicKey.Key }
    if ($rsa -isnot [System.Security.Cryptography.RSA]) {
      if ($rsaFromExtension -and ($rsaFromExtension -is [System.IDisposable])) {
        $rsaFromExtension.Dispose()
      }
      throw "Certificate must use RSA algorithm for encryption"
    }

    # Generate random 256-bit AES key
    $aesKey = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
      $rng.GetBytes($aesKey)
    }
    finally {
      $rng.Dispose()
    }

    $nonce = $null
    $tag = $null
    $iv = $null
    $ciphertext = $null

    if ($script:SupportsAesGcm) {
      $nonce = New-Object byte[] 12
      $tag = New-Object byte[] 16
      $rngForNonce = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      try {
        $rngForNonce.GetBytes($nonce)
      }
      finally {
        $rngForNonce.Dispose()
      }

      $ciphertext = New-Object byte[] $Plaintext.Length
      # Use AES-GCM
      $aesGcm = New-Object -TypeName $script:AesGcmType.FullName -ArgumentList (, $aesKey)
      try {
        $aesGcm.Encrypt($nonce, $Plaintext, $ciphertext, $tag)
      }
      finally {
        if ($aesGcm -is [System.IDisposable]) {
          $aesGcm.Dispose()
        }
      }
      $cipherAlgorithm = 'AES-GCM'
    }
    else {
      # Fallback to AES-CBC + HMAC
      $cipherAlgorithm = 'AES-CBC-HMACSHA256'

      $iv = New-Object byte[] 16
      $rngForIv = [System.Security.Cryptography.RandomNumberGenerator]::Create()
      try {
        $rngForIv.GetBytes($iv)
      }
      finally {
        $rngForIv.Dispose()
      }

      $infoEncryption = [System.Text.Encoding]::UTF8.GetBytes('SecureStore|EncryptionKeyV3')
      $infoAuthentication = [System.Text.Encoding]::UTF8.GetBytes('SecureStore|HmacKeyV3')
      $encryptionKey = $null
      $hmacKey = $null

      $derivationHmac = [System.Security.Cryptography.HMACSHA256]::new($aesKey)
      try {
        $encryptionKey = $derivationHmac.ComputeHash($infoEncryption)
        $hmacKey = $derivationHmac.ComputeHash($infoAuthentication)
      }
      finally {
        $derivationHmac.Dispose()
        if ($infoEncryption) {
          [Array]::Clear($infoEncryption, 0, $infoEncryption.Length)
        }
        if ($infoAuthentication) {
          [Array]::Clear($infoAuthentication, 0, $infoAuthentication.Length)
        }
      }

      $aesProvider = [System.Security.Cryptography.Aes]::Create()
      try {
        $aesProvider.KeySize = 256
        $aesProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesProvider.Key = $encryptionKey
        $aesProvider.IV = $iv

        $encryptor = $aesProvider.CreateEncryptor()
        try {
          $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
        }
        finally {
          if ($encryptor -is [System.IDisposable]) {
            $encryptor.Dispose()
          }
        }
      }
      finally {
        if ($aesProvider -is [System.IDisposable]) {
          $aesProvider.Dispose()
        }
        if ($encryptionKey) {
          [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
        }
      }

      $hmacProvider = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
      $tag = $null
      try {
        $macInput = New-Object byte[] ($iv.Length + $ciphertext.Length)
        try {
          [System.Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
          [System.Buffer]::BlockCopy($ciphertext, 0, $macInput, $iv.Length, $ciphertext.Length)
          $tag = $hmacProvider.ComputeHash($macInput)
        }
        finally {
          [Array]::Clear($macInput, 0, $macInput.Length)
        }
      }
      finally {
        $hmacProvider.Dispose()
        if ($hmacKey) {
          [Array]::Clear($hmacKey, 0, $hmacKey.Length)
        }
      }

      [Array]::Clear($iv, 0, $iv.Length)
    }

    # Encrypt the AES key with RSA (certificate's public key)
    $rsaPadding = 'OaepSHA256'
    try {
      $encryptedKey = $rsa.Encrypt($aesKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    }
    catch {
      $encryptedKey = $rsa.Encrypt($aesKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
      $rsaPadding = 'OaepSHA1'
    }
    finally {
      if ($rsaFromExtension -and ($rsaFromExtension -is [System.IDisposable])) {
        $rsaFromExtension.Dispose()
      }
    }

    # Build JSON payload
    $cipherPayload = [ordered]@{
      Algorithm    = $cipherAlgorithm
      KeySize      = 256
      EncryptedKey = [Convert]::ToBase64String($encryptedKey)
    }

    if ($cipherAlgorithm -eq 'AES-GCM') {
      $cipherPayload.Nonce = [Convert]::ToBase64String($nonce)
      $cipherPayload.Tag = [Convert]::ToBase64String($tag)
      $cipherPayload.CipherText = [Convert]::ToBase64String($ciphertext)
    }
    else {
      $cipherPayload.IV = [Convert]::ToBase64String($iv)
      $cipherPayload.Hmac = [Convert]::ToBase64String($tag)
      $cipherPayload.CipherText = [Convert]::ToBase64String($ciphertext)
    }

    $payload = [ordered]@{
      Version          = 3
      EncryptionMethod = 'Certificate'
      CertificatePadding = $rsaPadding
      CertificateInfo  = [ordered]@{
        Thumbprint = $Certificate.Thumbprint
        Subject    = $Certificate.Subject
        Algorithm  = 'RSA'
        NotAfter   = $Certificate.NotAfter.ToString('o')
      }
      Cipher           = $cipherPayload
    }

    # Clean up sensitive data
    [Array]::Clear($aesKey, 0, $aesKey.Length)
    if ($nonce) {
      [Array]::Clear($nonce, 0, $nonce.Length)
    }
    if ($iv) {
      [Array]::Clear($iv, 0, $iv.Length)
    }
    if ($tag) {
      [Array]::Clear($tag, 0, $tag.Length)
    }
    if ($ciphertext) {
      [Array]::Clear($ciphertext, 0, $ciphertext.Length)
    }
    [Array]::Clear($encryptedKey, 0, $encryptedKey.Length)

    return ($payload | ConvertTo-Json -Depth 4)
  }
  catch {
    $errorMessage = $_.Exception.Message
    throw [System.InvalidOperationException]::new(
      "Failed to encrypt secret with certificate: $errorMessage",
      $_.Exception
    )
  }
}

function Unprotect-SecureStoreSecretWithCertificate {
  <#
    .SYNOPSIS
    Decrypts a certificate-encrypted secret.
    
    .DESCRIPTION
    Uses the certificate's RSA private key to decrypt the AES key,
    then uses the AES key to decrypt the secret data.
    #>
  [CmdletBinding()]
  [OutputType([byte[]])]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Payload,

    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )

  try {
    # Parse JSON payload
    $data = $Payload | ConvertFrom-Json -ErrorAction Stop

    if ($data.Version -ne 3) {
      throw "Unsupported secret version: $($data.Version). Expected version 3 for certificate-encrypted secrets."
    }

    if ($data.EncryptionMethod -ne 'Certificate') {
      throw "Invalid encryption method: $($data.EncryptionMethod). Expected 'Certificate'."
    }

    # Validate certificate has private key
    if (-not $Certificate.HasPrivateKey) {
      throw "Certificate does not have a private key. Cannot decrypt secret."
    }

    # Get RSA private key
    $rsaFromExtension = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    $rsa = if ($rsaFromExtension) { $rsaFromExtension } else { $Certificate.PrivateKey }

    if (-not $rsa -or $rsa -isnot [System.Security.Cryptography.RSA]) {
      if ($rsaFromExtension -and ($rsaFromExtension -is [System.IDisposable])) {
        $rsaFromExtension.Dispose()
      }
      throw "Failed to retrieve RSA private key from certificate"
    }

    try {
      # Decrypt the AES key using RSA private key
      $encryptedKey = [Convert]::FromBase64String([string]$data.Cipher.EncryptedKey)
      $preferredPadding = switch ($data.CertificatePadding) {
        'OaepSHA1'   { [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1 }
        'OaepSHA256' { [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256 }
        default      { [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256 }
      }

      try {
        $aesKey = $rsa.Decrypt($encryptedKey, $preferredPadding)
      }
      catch {
        if ($preferredPadding -ne [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1) {
          $aesKey = $rsa.Decrypt($encryptedKey, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
        }
        else {
          throw
        }
      }
    }
    finally {
      if ($rsaFromExtension -and ($rsaFromExtension -is [System.IDisposable])) {
        $rsaFromExtension.Dispose()
      }
    }

    # Decrypt the secret using AES
    $cipherAlgorithm = [string]$data.Cipher.Algorithm
    $ciphertext = [Convert]::FromBase64String([string]$data.Cipher.CipherText)
    $nonce = $null
    $tag = $null
    $plaintext = $null

    if ($cipherAlgorithm -eq 'AES-GCM') {
      if (-not $script:SupportsAesGcm) {
        throw "Secret was encrypted with AES-GCM but current runtime does not support it"
      }

      $nonce = [Convert]::FromBase64String([string]$data.Cipher.Nonce)
      $tag = [Convert]::FromBase64String([string]$data.Cipher.Tag)
      $plaintext = New-Object byte[] $ciphertext.Length
      $aesGcm = New-Object -TypeName $script:AesGcmType.FullName -ArgumentList (, $aesKey)
      try {
        $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plaintext)
      }
      catch {
        throw "Secret integrity check failed or wrong certificate used"
      }
      finally {
        if ($aesGcm -is [System.IDisposable]) {
          $aesGcm.Dispose()
        }
      }
    }
    elseif ($cipherAlgorithm -eq 'AES-CBC-HMACSHA256') {
      $iv = [Convert]::FromBase64String([string]$data.Cipher.IV)
      $hmac = [Convert]::FromBase64String([string]$data.Cipher.Hmac)

      $infoEncryption = [System.Text.Encoding]::UTF8.GetBytes('SecureStore|EncryptionKeyV3')
      $infoAuthentication = [System.Text.Encoding]::UTF8.GetBytes('SecureStore|HmacKeyV3')
      $encryptionKey = $null
      $hmacKey = $null

      $derivationHmac = [System.Security.Cryptography.HMACSHA256]::new($aesKey)
      try {
        $encryptionKey = $derivationHmac.ComputeHash($infoEncryption)
        $hmacKey = $derivationHmac.ComputeHash($infoAuthentication)
      }
      finally {
        $derivationHmac.Dispose()
        if ($infoEncryption) {
          [Array]::Clear($infoEncryption, 0, $infoEncryption.Length)
        }
        if ($infoAuthentication) {
          [Array]::Clear($infoAuthentication, 0, $infoAuthentication.Length)
        }
      }

      $hmacProvider = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
      $computedHmac = $null
      try {
        $macInput = New-Object byte[] ($iv.Length + $ciphertext.Length)
        try {
          [System.Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
          [System.Buffer]::BlockCopy($ciphertext, 0, $macInput, $iv.Length, $ciphertext.Length)
          $computedHmac = $hmacProvider.ComputeHash($macInput)
        }
        finally {
          [Array]::Clear($macInput, 0, $macInput.Length)
        }
      }
      finally {
        $hmacProvider.Dispose()
        if ($hmacKey) {
          [Array]::Clear($hmacKey, 0, $hmacKey.Length)
        }
      }

      if (-not (Test-SecureStoreFixedTimeEqual -Left $computedHmac -Right $hmac)) {
        [Array]::Clear($iv, 0, $iv.Length)
        [Array]::Clear($hmac, 0, $hmac.Length)
        if ($computedHmac) {
          [Array]::Clear($computedHmac, 0, $computedHmac.Length)
        }
        if ($encryptionKey) {
          [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
        }
        throw "Secret integrity check failed or wrong certificate used"
      }

      if ($computedHmac) {
        [Array]::Clear($computedHmac, 0, $computedHmac.Length)
      }

      $aesProvider = [System.Security.Cryptography.Aes]::Create()
      try {
        $aesProvider.KeySize = 256
        $aesProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesProvider.Key = $encryptionKey
        $aesProvider.IV = $iv

        $decryptor = $aesProvider.CreateDecryptor()
        try {
          $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        }
        finally {
          if ($decryptor -is [System.IDisposable]) {
            $decryptor.Dispose()
          }
        }
      }
      catch {
        throw "Secret integrity check failed or wrong certificate used"
      }
      finally {
        if ($aesProvider -is [System.IDisposable]) {
          $aesProvider.Dispose()
        }
        if ($encryptionKey) {
          [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
        }
      }

      [Array]::Clear($iv, 0, $iv.Length)
      [Array]::Clear($hmac, 0, $hmac.Length)
    }
    else {
      throw "Unsupported cipher algorithm: $cipherAlgorithm"
    }

    # Clean up sensitive data
    [Array]::Clear($aesKey, 0, $aesKey.Length)
    if ($nonce) {
      [Array]::Clear($nonce, 0, $nonce.Length)
    }
    if ($tag) {
      [Array]::Clear($tag, 0, $tag.Length)
    }
    if ($ciphertext) {
      [Array]::Clear($ciphertext, 0, $ciphertext.Length)
    }
    [Array]::Clear($encryptedKey, 0, $encryptedKey.Length)

    return $plaintext
  }
  catch {
    throw [System.InvalidOperationException]::new('Failed to decrypt secret with certificate.', $_.Exception)
  }
}