<#
.SYNOPSIS
Retrieves a stored SecureStore secret as plain text or PSCredential.

.DESCRIPTION
Get‑SecureStoreSecret locates the associated encryption key and secret payload by logical name
or explicit paths, decrypts the payload while enforcing integrity checks, and returns either a
plain text string or PSCredential.  It automatically handles both AES‑based secrets (version 2)
and certificate‑encrypted secrets (version 3).  For version 3 secrets you may specify
-CertificateThumbprint or -CertificatePath/-CertificatePassword to decrypt with a specific
certificate; otherwise the cmdlet will auto‑detect the thumbprint from the secret metadata
and search the local certificate stores.

.PARAMETER KeyName
Logical key identifier when using the default folder layout.  Required for AES‑based secrets.

.PARAMETER SecretFileName
Secret file name beneath the SecureStore secrets directory.

.PARAMETER KeyPath
Direct path to a .bin key file when bypassing the default layout.

.PARAMETER SecretPath
Direct path to an encrypted secret file when bypassing the default layout.

.PARAMETER FolderPath
Base path of the SecureStore repository.  Defaults to the platform-specific location.

.PARAMETER AsCredential
Return the secret as a PSCredential instance instead of plain text.

.PARAMETER UserName
Username associated with the PSCredential output.  Ignored unless -AsCredential is specified.

.PARAMETER CertificateThumbprint
Thumbprint of the certificate containing the private key used to decrypt a version 3 secret.

.PARAMETER CertificatePath
Path to a PFX file containing the certificate/private key used to decrypt a version 3 secret.

.PARAMETER CertificatePassword
Password used to open the PFX file specified by -CertificatePath.

.OUTPUTS
System.String or System.Management.Automation.PSCredential.

.EXAMPLE
Get-SecureStoreSecret -KeyName 'WebApp' -SecretFileName 'service.secret'

Retrieves the decrypted secret value stored for WebApp and returns it as plain text.

.EXAMPLE
Get-SecureStoreSecret -SecretFileName 'service.secret' -CertificateThumbprint 'ABC123' -AsCredential -UserName 'svc-web'

Decrypts a certificate-protected secret and returns it as a PSCredential using the provided user name.

.NOTES
Certificate-based secrets (version 3) require access to the private key either via LocalMachine/CurrentUser certificate stores or by providing a PFX path/password.
#>
function Get-SecureStoreSecret {
  [CmdletBinding(DefaultParameterSetName = 'ByName')]
  [OutputType([string])]
  [OutputType([System.Management.Automation.PSCredential])]
  param(
    [Parameter(ParameterSetName = 'ByName')]
    [ValidateNotNullOrEmpty()]
    [string]$KeyName,

    [Parameter(ParameterSetName = 'ByName', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretFileName,

    [Parameter(ParameterSetName = 'ByPath', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyPath,

    [Parameter(ParameterSetName = 'ByPath', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SecretPath,

    [Parameter(ParameterSetName = 'ByName')]
    [ValidateNotNullOrEmpty()]
    [string]$FolderPath = $script:DefaultSecureStorePath,

    [Parameter()]
    [switch]$AsCredential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$UserName = 'user',

    [Parameter()]
    [string]$CertificateThumbprint,

    [Parameter()]
    [string]$CertificatePath,

    [Parameter()]
    [object]$CertificatePassword
  )

  begin {
    if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
      . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
    }
  }

  process {
    $encryptionKey = $null
    $keyFilePath = $null
    $plaintextBytes = $null
    $securePassword = $null
    $privateKey = $null
    $cert = $null
    try {
      # Resolve candidate secret files (supporting legacy paths)
      $secretCandidates = New-Object System.Collections.Generic.List[string]
      $seenCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
      $addCandidate = {
        param([string]$Candidate)
        if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
        $resolvedCandidate = [System.IO.Path]::GetFullPath($Candidate)
        if ($seenCandidates.Add($resolvedCandidate)) {
          [void]$secretCandidates.Add($resolvedCandidate)
        }
      }

      $paths = $null
      switch ($PSCmdlet.ParameterSetName) {
        'ByPath' {
          $keyFilePath = Resolve-SecureStorePath -Path $KeyPath -BasePath (Get-Location).Path
          $explicitSecretPath = Resolve-SecureStorePath -Path $SecretPath -BasePath (Get-Location).Path
          & $addCandidate $explicitSecretPath

          $secretDirectory = Split-Path -Path $explicitSecretPath -Parent
          if ($secretDirectory) {
            $leaf = Split-Path -Path $secretDirectory -Leaf
            if ($leaf -and $leaf.Equals('secret', [System.StringComparison]::OrdinalIgnoreCase)) {
              $preferredDirectory = Join-Path -Path (Split-Path -Path $secretDirectory -Parent) -ChildPath 'secrets'
              $preferredFromExplicit = Join-Path -Path $preferredDirectory -ChildPath (Split-Path -Path $explicitSecretPath -Leaf)
              & $addCandidate $preferredFromExplicit
            }
          }
        }
        default {
          $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

          if ($PSBoundParameters.ContainsKey('KeyName') -and -not [string]::IsNullOrWhiteSpace($KeyName)) {
            if (Test-SecureStorePathLike -Value $KeyName) {
              $keyFilePath = Resolve-SecureStorePath -Path $KeyName -BasePath $paths.BasePath
            }
            else {
              $keyChild = if ($KeyName.EndsWith('.bin', [System.StringComparison]::OrdinalIgnoreCase)) { $KeyName } else { "$KeyName.bin" }
              $keyFilePath = Join-Path -Path $paths.BinPath -ChildPath $keyChild
            }
          }

          if (Test-SecureStorePathLike -Value $SecretFileName) {
            $explicitSecretPath = Resolve-SecureStorePath -Path $SecretFileName -BasePath $paths.BasePath
            $preferredSecretPath = ConvertTo-SecureStorePreferredSecretPath -Path $explicitSecretPath -PreferredSecretDir $paths.SecretPath -LegacySecretDir $paths.LegacySecretPath
            & $addCandidate $preferredSecretPath
            & $addCandidate $explicitSecretPath

            if ($paths.LegacySecretPath) {
              $relativeSecretPath = Get-SecureStoreRelativePath -BasePath $paths.SecretPath -TargetPath $preferredSecretPath
              if ($null -ne $relativeSecretPath) {
                $legacyCandidate = if ([string]::IsNullOrWhiteSpace($relativeSecretPath)) { $paths.LegacySecretPath } else { Join-Path -Path $paths.LegacySecretPath -ChildPath $relativeSecretPath }
                & $addCandidate $legacyCandidate
              }
            }
          }
          else {
            $preferredSecretPath = Join-Path -Path $paths.SecretPath -ChildPath $SecretFileName
            & $addCandidate $preferredSecretPath
            if ($paths.LegacySecretPath) {
              $legacyCandidate = Join-Path -Path $paths.LegacySecretPath -ChildPath $SecretFileName
              & $addCandidate $legacyCandidate
            }
          }
        }
      }

      # Identify the first existing secret file
      $secretFilePath = $null
      foreach ($candidate in $secretCandidates) {
        if (Test-Path -LiteralPath $candidate) {
          $secretFilePath = $candidate
          break
        }
      }
      if (-not $secretFilePath) {
        $fallbackTarget = if ($secretCandidates.Count -gt 0) { $secretCandidates[0] } else { $SecretFileName }
        throw [System.IO.FileNotFoundException]::new('The encrypted payload file could not be located.', $fallbackTarget)
      }

      # Read encrypted payload text
      $encryptedPayload = Read-SecureStoreText -Path $secretFilePath -Encoding ([System.Text.Encoding]::UTF8)

      # Attempt to parse JSON; version 3 secrets are JSON with Version=3
      $parsed = $null
      $isJson = $false
      try {
        $parsed = $encryptedPayload | ConvertFrom-Json -ErrorAction Stop
        $isJson = $true
      }
      catch {
        $isJson = $false
      }

      # Determine payload version to support both AES (v2) and certificate (v3) secrets.
      $secretVersion = 2
      if ($isJson -and $parsed.PSObject.Properties['Version']) {
        $versionCandidate = [string]$parsed.Version
        $parsedVersion = 0
        if ([int]::TryParse($versionCandidate, [ref]$parsedVersion)) {
          $secretVersion = $parsedVersion
        }
        elseif ($parsed.Version -is [int]) {
          $secretVersion = [int]$parsed.Version
        }
      }

      switch ($secretVersion) {
        3 {
          if ($parsed.EncryptionMethod -ne 'Certificate') {
            throw [System.InvalidOperationException]::new("Unsupported encryption method '$($parsed.EncryptionMethod)' for version 3 payloads.")
          }

          if (-not (Get-Command -Name 'Unprotect-SecureStoreSecretWithCertificate' -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot/Get-SecureStoreCertificateForEncryption.ps1"
          }
          if (-not (Get-Command -Name 'Get-SecureStoreCertificateForEncryption' -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot/Get-SecureStoreCertificateForEncryption.ps1"
          }

          try {
            if (-not $PSBoundParameters.ContainsKey('CertificateThumbprint') -and -not $PSBoundParameters.ContainsKey('CertificatePath')) {
              if (-not ($parsed.CertificateInfo -and $parsed.CertificateInfo.PSObject.Properties['Thumbprint'])) {
                throw [System.InvalidOperationException]::new('Secret metadata does not include a certificate thumbprint. Provide -CertificateThumbprint or -CertificatePath.')
              }

              $thumb = [string]$parsed.CertificateInfo.Thumbprint
              if ([string]::IsNullOrWhiteSpace($thumb)) {
                throw [System.InvalidOperationException]::new('Secret metadata includes an empty certificate thumbprint. Provide -CertificateThumbprint or -CertificatePath.')
              }

              $thumb = $thumb.Replace(' ', '')
              $cert = Get-SecureStoreCertificateForEncryption -Thumbprint $thumb -RequirePrivateKey
            }
            elseif ($PSBoundParameters.ContainsKey('CertificatePath')) {
              $parameters = @{ CertificatePath = $CertificatePath; RequirePrivateKey = $true }
              if ($PSBoundParameters.ContainsKey('CertificatePassword')) {
                $parameters['Password'] = $CertificatePassword
              }
              $cert = Get-SecureStoreCertificateForEncryption @parameters
            }
            else {
              $thumb = $CertificateThumbprint.Replace(' ', '')
              $cert = Get-SecureStoreCertificateForEncryption -Thumbprint $thumb -RequirePrivateKey
            }
          }
          catch {
            throw [System.InvalidOperationException]::new(
              "Failed to load certificate for decryption: $($_.Exception.Message)",
              $_.Exception
            )
          }

          if (-not $cert) {
            throw [System.InvalidOperationException]::new('Unable to obtain a certificate for decryption.')
          }

          $hasHybridPayload = $false
          if ($parsed -and $parsed.PSObject.Properties['Cipher']) {
            $hasHybridPayload = $true
          }

          if ($hasHybridPayload) {
            $plaintextBytes = Unprotect-SecureStoreSecretWithCertificate -Payload $encryptedPayload -Certificate $cert
          }
          else {
            $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if (-not $privateKey) {
              throw [System.InvalidOperationException]::new('The certificate does not have an RSA private key.')
            }

            $encryptedBytes = [Convert]::FromBase64String($parsed.EncryptedData)
            $plaintextBytes = $privateKey.Decrypt($encryptedBytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
          }

          $chars = [System.Text.Encoding]::UTF8.GetChars($plaintextBytes)
          try {
            $securePassword = New-Object System.Security.SecureString
            foreach ($char in $chars) { $securePassword.AppendChar($char) }
            $securePassword.MakeReadOnly()
          }
          finally {
            [Array]::Clear($chars, 0, $chars.Length)
          }

          if ($AsCredential.IsPresent) {
            return New-Object System.Management.Automation.PSCredential($UserName, $securePassword.Copy())
          }

          $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
          try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
          }
          finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
          }
        }
        default {
          if (-not $keyFilePath) {
            throw [System.IO.FileNotFoundException]::new('The encryption key file could not be located.', $keyFilePath)
          }
          if (-not (Test-Path -LiteralPath $keyFilePath)) {
            throw [System.IO.FileNotFoundException]::new('The encryption key file could not be located.', $keyFilePath)
          }
          $encryptionKey = Read-SecureStoreByteArray -Path $keyFilePath
          $encryptedPassword = $encryptedPayload
          $plaintextBytes = Unprotect-SecureStoreSecret -Payload $encryptedPassword -MasterKey $encryptionKey

          $chars = [System.Text.Encoding]::UTF8.GetChars($plaintextBytes)
          try {
            $securePassword = New-Object System.Security.SecureString
            foreach ($char in $chars) { $securePassword.AppendChar($char) }
            $securePassword.MakeReadOnly()
          }
          finally {
            [Array]::Clear($chars, 0, $chars.Length)
          }

          if ($AsCredential.IsPresent) {
            return New-Object System.Management.Automation.PSCredential($UserName, $securePassword.Copy())
          }

          $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
          try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
          }
          finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
          }
        }
      }
    }
    catch {
      $errorMessage = $_.Exception.Message
      $targetName = if ($secretFilePath) { $secretFilePath } else { $SecretFileName }
      $displayTarget = $targetName
      if ($displayTarget) {
        $displayTarget = [System.Text.RegularExpressions.Regex]::Replace(
          $displayTarget,
          'secret',
          'entry',
          [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
      }
      throw [System.InvalidOperationException]::new(
        "Failed to retrieve SecureStore entry at '$displayTarget': $errorMessage",
        $_.Exception
      )
    }
    finally {
      if ($securePassword) { $securePassword.Dispose() }
      if ($plaintextBytes) { [Array]::Clear($plaintextBytes, 0, $plaintextBytes.Length) }
      if ($encryptionKey) { [Array]::Clear($encryptionKey, 0, $encryptionKey.Length) }
      if ($privateKey) { $privateKey.Dispose() }
      if ($cert -and ($cert -is [System.IDisposable])) { $cert.Dispose() }
    }
  }
}
