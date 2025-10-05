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

          $certificateInfo = $parsed.CertificateInfo
          $expectedThumbprint = $null
          if ($certificateInfo -and $certificateInfo.PSObject.Properties['Thumbprint']) {
            $expectedThumbprint = [string]$certificateInfo.Thumbprint
            if (-not [string]::IsNullOrWhiteSpace($expectedThumbprint)) {
              $expectedThumbprint = $expectedThumbprint.Replace(' ', '')
            }
            else {
              $expectedThumbprint = $null
            }
          }

          $resolutionBase = $null
          if ($paths -and $paths.PSObject.Properties['BasePath']) {
            $resolutionBase = $paths.BasePath
          }
          elseif ($secretFilePath) {
            $resolutionBase = Split-Path -Path $secretFilePath -Parent
          }
          if (-not $resolutionBase) {
            $resolutionBase = (Get-Location).Path
          }

          $metadataCertificatePath = $null
          $metadataCertificateFileName = $null
          $metadataPasswordProtected = $false

          if ($certificateInfo) {
            if ($certificateInfo.PSObject.Properties['Path']) {
              $rawPath = [string]$certificateInfo.Path
              if (-not [string]::IsNullOrWhiteSpace($rawPath)) {
                try {
                  $metadataCertificatePath = Resolve-SecureStorePath -Path $rawPath -BasePath $resolutionBase
                }
                catch {
                  try {
                    $metadataCertificatePath = [System.IO.Path]::GetFullPath($rawPath)
                  }
                  catch {
                    $metadataCertificatePath = $rawPath
                  }
                }
              }
            }

            if ($certificateInfo.PSObject.Properties['FileName']) {
              $metadataCertificateFileName = [string]$certificateInfo.FileName
              if ([string]::IsNullOrWhiteSpace($metadataCertificateFileName)) {
                $metadataCertificateFileName = $null
              }
            }

            if ($certificateInfo.PSObject.Properties['PasswordProtected']) {
              try {
                $metadataPasswordProtected = [bool]$certificateInfo.PasswordProtected
              }
              catch {
                $metadataPasswordProtected = $false
              }
            }
          }

          $requestedThumbprint = $null
          $requestedCertificatePath = $null
          $certificateSourceDescription = $null
          $primaryLoadError = $null
          $loadErrorMessages = New-Object 'System.Collections.Generic.List[string]'

          if ($PSBoundParameters.ContainsKey('CertificatePath')) {
            try {
              $requestedCertificatePath = Resolve-SecureStorePath -Path $CertificatePath -BasePath $resolutionBase
            }
            catch {
              try {
                $requestedCertificatePath = [System.IO.Path]::GetFullPath($CertificatePath)
              }
              catch {
                $requestedCertificatePath = $CertificatePath
              }
            }

            $parameters = @{ CertificatePath = $requestedCertificatePath; RequirePrivateKey = $true }
            if ($PSBoundParameters.ContainsKey('CertificatePassword')) {
              $parameters['Password'] = $CertificatePassword
            }

            try {
              $candidate = Get-SecureStoreCertificateForEncryption @parameters
              if ($candidate) {
                if ($expectedThumbprint -and $candidate.Thumbprint.Replace(' ', '') -ne $expectedThumbprint) {
                  if ($candidate -is [System.IDisposable]) { $candidate.Dispose() }
                  throw [System.InvalidOperationException]::new("Certificate thumbprint '$($candidate.Thumbprint)' does not match expected thumbprint '$expectedThumbprint'.")
                }
                $cert = $candidate
                $certificateSourceDescription = "certificate file '$requestedCertificatePath'"
              }
            }
            catch {
              if (-not $primaryLoadError) { $primaryLoadError = $_ }
              $message = $_.Exception.Message
              if (-not [string]::IsNullOrWhiteSpace($message)) { $null = $loadErrorMessages.Add($message) }
            }
          }
          elseif ($PSBoundParameters.ContainsKey('CertificateThumbprint')) {
            $thumb = $CertificateThumbprint.Replace(' ', '')
            $requestedThumbprint = $thumb
            try {
              $candidate = Get-SecureStoreCertificateForEncryption -Thumbprint $thumb -RequirePrivateKey
              if ($candidate) {
                $cert = $candidate
                $certificateSourceDescription = "certificate with thumbprint '$thumb'"
              }
            }
            catch {
              if (-not $primaryLoadError) { $primaryLoadError = $_ }
              $message = $_.Exception.Message
              if (-not [string]::IsNullOrWhiteSpace($message)) { $null = $loadErrorMessages.Add($message) }
            }
          }
          else {
            if (-not $expectedThumbprint) {
              throw [System.InvalidOperationException]::new('Secret metadata does not include a certificate thumbprint. Provide -CertificateThumbprint or -CertificatePath.')
            }

            $requestedThumbprint = $expectedThumbprint
            try {
              $candidate = Get-SecureStoreCertificateForEncryption -Thumbprint $expectedThumbprint -RequirePrivateKey
              if ($candidate) {
                $cert = $candidate
                $certificateSourceDescription = "certificate with thumbprint '$expectedThumbprint'"
              }
            }
            catch {
              if (-not $primaryLoadError) { $primaryLoadError = $_ }
              $message = $_.Exception.Message
              if (-not [string]::IsNullOrWhiteSpace($message)) { $null = $loadErrorMessages.Add($message) }
            }

            if (-not $cert -and $metadataCertificatePath) {
              $loadParams = @{ CertificatePath = $metadataCertificatePath; RequirePrivateKey = $true }
              if ($PSBoundParameters.ContainsKey('CertificatePassword')) {
                $loadParams['Password'] = $CertificatePassword
              }

              try {
                $candidate = Get-SecureStoreCertificateForEncryption @loadParams
                if ($candidate) {
                  if ($candidate.Thumbprint.Replace(' ', '') -ne $expectedThumbprint) {
                    if ($candidate -is [System.IDisposable]) { $candidate.Dispose() }
                    throw [System.InvalidOperationException]::new("Certificate thumbprint '$($candidate.Thumbprint)' does not match expected thumbprint '$expectedThumbprint'.")
                  }
                  $cert = $candidate
                  $certificateSourceDescription = "certificate file '$metadataCertificatePath'"
                  $requestedCertificatePath = $metadataCertificatePath
                }
              }
              catch {
                if (-not $primaryLoadError) { $primaryLoadError = $_ }
                $message = $_.Exception.Message
                if (-not [string]::IsNullOrWhiteSpace($message)) { $null = $loadErrorMessages.Add($message) }
              }
            }
          }

          if (-not $cert) {
            if ($metadataCertificatePath -and $metadataPasswordProtected -and -not $PSBoundParameters.ContainsKey('CertificatePassword')) {
              $identifierMessage = "PFX file '$metadataCertificatePath'"
              throw [System.InvalidOperationException]::new("$identifierMessage requires a password. Provide -CertificatePassword to decrypt the secret.")
            }

            $targetThumbprint = if ($expectedThumbprint) { $expectedThumbprint } elseif ($requestedThumbprint) { $requestedThumbprint } else { $null }
            $fallbackCertificate = $null
            $fallbackSource = $null
            $fallbackPath = $null

            $candidateDirectories = New-Object System.Collections.Generic.List[string]
            $directorySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $addDirectory = {
              param([string]$Directory)
              if ([string]::IsNullOrWhiteSpace($Directory)) { return }
              try {
                $fullPath = [System.IO.Path]::GetFullPath($Directory)
              }
              catch {
                return
              }
              if ($directorySet.Add($fullPath)) {
                [void]$candidateDirectories.Add($fullPath)
              }
            }

            if ($metadataCertificatePath) {
              $metadataDirectory = $null
              try {
                $metadataDirectory = Split-Path -Path $metadataCertificatePath -Parent
              }
              catch {
                $metadataDirectory = $null
              }
              if ($metadataDirectory) { & $addDirectory $metadataDirectory }
            }

            if ($paths -and $paths.PSObject.Properties['CertsPath']) {
              & $addDirectory $paths.CertsPath
            }

            if ($secretFilePath) {
              $secretDir = Split-Path -Path $secretFilePath -Parent
              if ($secretDir) {
                $baseDir = Split-Path -Path $secretDir -Parent
                if ($baseDir) {
                  & $addDirectory (Join-Path -Path $baseDir -ChildPath 'certs')
                }
              }
            }

            $candidateFiles = New-Object System.Collections.Generic.List[string]
            $fileSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $addFile = {
              param([string]$FilePath)
              if ([string]::IsNullOrWhiteSpace($FilePath)) { return }
              try {
                $fullFilePath = [System.IO.Path]::GetFullPath($FilePath)
              }
              catch {
                return
              }
              if ($fileSet.Add($fullFilePath)) {
                [void]$candidateFiles.Add($fullFilePath)
              }
            }

            if ($metadataCertificatePath -and (Test-Path -LiteralPath $metadataCertificatePath)) {
              & $addFile $metadataCertificatePath
            }

            if ($metadataCertificateFileName) {
              foreach ($directory in $candidateDirectories) {
                $explicitCandidate = Join-Path -Path $directory -ChildPath $metadataCertificateFileName
                if (Test-Path -LiteralPath $explicitCandidate) {
                  & $addFile $explicitCandidate
                }
              }
            }

            foreach ($directory in $candidateDirectories) {
              if (-not (Test-Path -LiteralPath $directory)) { continue }
              $pfxFiles = Get-ChildItem -LiteralPath $directory -Filter '*.pfx' -File -ErrorAction SilentlyContinue
              foreach ($file in $pfxFiles) {
                & $addFile $file.FullName
              }
            }

            if ($candidateFiles.Count -gt 0) {
              $passwordCandidates = New-Object 'System.Collections.Generic.List[object]'
              $createdEmptyPassword = $false

              if ($PSBoundParameters.ContainsKey('CertificatePassword')) {
                [void]$passwordCandidates.Add($CertificatePassword)
              }
              elseif (-not $metadataPasswordProtected) {
                $emptyPassword = New-Object System.Security.SecureString
                $emptyPassword.MakeReadOnly()
                [void]$passwordCandidates.Add($emptyPassword)
                $createdEmptyPassword = $true
              }

              foreach ($pfxPath in $candidateFiles) {
                foreach ($passwordCandidate in $passwordCandidates) {
                  $loadParams = @{ CertificatePath = $pfxPath; RequirePrivateKey = $true }
                  if ($passwordCandidate) {
                    $loadParams['Password'] = $passwordCandidate
                  }

                  $candidate = $null
                  try {
                    $candidate = Get-SecureStoreCertificateForEncryption @loadParams
                    if ($candidate) {
                      $candidateThumbprint = $candidate.Thumbprint.Replace(' ', '')
                      if (-not $targetThumbprint -or $candidateThumbprint -eq $targetThumbprint) {
                        $fallbackCertificate = $candidate
                        $fallbackSource = "certificate file '$pfxPath'"
                        $fallbackPath = $pfxPath
                        break
                      }

                      if ($candidate -is [System.IDisposable]) {
                        $candidate.Dispose()
                      }
                    }
                  }
                  catch {
                    if (-not $primaryLoadError) { $primaryLoadError = $_ }
                    $message = $_.Exception.Message
                    if (-not [string]::IsNullOrWhiteSpace($message)) { $null = $loadErrorMessages.Add($message) }
                  }
                }

                if ($fallbackCertificate) {
                  break
                }
              }

              if ($createdEmptyPassword -and $passwordCandidates.Count -gt 0) {
                $firstPassword = $passwordCandidates[0]
                if ($firstPassword -is [System.IDisposable]) {
                  $firstPassword.Dispose()
                }
              }
            }

            if ($fallbackCertificate) {
              $cert = $fallbackCertificate
              $certificateSourceDescription = $fallbackSource
              if (-not $requestedCertificatePath -and $fallbackPath) {
                $requestedCertificatePath = $fallbackPath
              }
            }
          }

          if (-not $cert) {
            $identifier = if ($requestedThumbprint) {
              "certificate with thumbprint '$requestedThumbprint'"
            }
            elseif ($requestedCertificatePath) {
              "certificate file '$requestedCertificatePath'"
            }
            elseif ($expectedThumbprint) {
              "certificate with thumbprint '$expectedThumbprint'"
            }
            elseif ($metadataCertificatePath) {
              "certificate file '$metadataCertificatePath'"
            }
            else {
              'certificate with a matching private key'
            }

            if ($primaryLoadError) {
              $loadMessage = $primaryLoadError.Exception.Message
              throw [System.InvalidOperationException]::new(
                "Failed to load ${identifier}: $loadMessage",
                $primaryLoadError.Exception
              )
            }

            throw [System.InvalidOperationException]::new("Unable to locate $identifier required to decrypt the secret.")
          }

          if ($certificateInfo -and $certificateInfo.PSObject.Properties['Algorithm']) {
            $expectedAlgorithm = [string]$certificateInfo.Algorithm
            if (-not [string]::IsNullOrWhiteSpace($expectedAlgorithm)) {
              $actualAlgorithm = 'RSA'
              try {
                if ($cert.PublicKey -and $cert.PublicKey.Oid -and $cert.PublicKey.Oid.FriendlyName) {
                  $actualAlgorithm = $cert.PublicKey.Oid.FriendlyName
                }
              }
              catch {
                $actualAlgorithm = 'RSA'
              }

              if (-not $expectedAlgorithm.Equals($actualAlgorithm, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw [System.InvalidOperationException]::new("Loaded certificate algorithm '$actualAlgorithm' does not match expected algorithm '$expectedAlgorithm'.")
              }
            }
          }

          $certificateIdentifier = $certificateSourceDescription
          if (-not $certificateIdentifier -and $cert -and $cert.Thumbprint) {
            $certificateIdentifier = "certificate with thumbprint '$($cert.Thumbprint.Replace(' ', ''))'"
          }
          if (-not $certificateIdentifier -and $requestedThumbprint) {
            $certificateIdentifier = "certificate with thumbprint '$requestedThumbprint'"
          }
          if (-not $certificateIdentifier -and $requestedCertificatePath) {
            $certificateIdentifier = "certificate file '$requestedCertificatePath'"
          }
          if (-not $certificateIdentifier -and $metadataCertificatePath) {
            $certificateIdentifier = "certificate file '$metadataCertificatePath'"
          }
          if (-not $certificateIdentifier -and $metadataCertificateFileName) {
            $certificateIdentifier = "certificate file '$metadataCertificateFileName'"
          }
          if (-not $certificateIdentifier) {
            $certificateIdentifier = 'specified certificate'
          }

          $hasHybridPayload = $false
          if ($parsed -and $parsed.PSObject.Properties['Cipher']) {
            $hasHybridPayload = $true
          }

          if ($hasHybridPayload) {
            try {
              $plaintextBytes = Unprotect-SecureStoreSecretWithCertificate -Payload $encryptedPayload -Certificate $cert
            }
            catch {
              $innerMessage = $_.Exception.Message
              if (-not [string]::IsNullOrWhiteSpace($innerMessage)) {
                $prefix = 'Failed to decrypt secret with certificate:'
                if ($innerMessage.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                  $innerMessage = $innerMessage.Substring($prefix.Length)
                }
                $innerMessage = $innerMessage.Trim()
              }
              $errorMessage = if ([string]::IsNullOrWhiteSpace($innerMessage)) {
                "Failed to decrypt secret with certificate ($certificateIdentifier)."
              }
              else {
                "Failed to decrypt secret with certificate ($certificateIdentifier): $innerMessage"
              }
              throw [System.InvalidOperationException]::new($errorMessage, $_.Exception)
            }
          }
          else {
            try {
              $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
              if (-not $privateKey) {
                throw [System.InvalidOperationException]::new('The certificate does not have an RSA private key.')
              }

              $encryptedBytes = [Convert]::FromBase64String($parsed.EncryptedData)
              $plaintextBytes = $privateKey.Decrypt($encryptedBytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
              $innerMessage = $_.Exception.Message
              if (-not [string]::IsNullOrWhiteSpace($innerMessage)) {
                $prefix = 'Failed to decrypt secret with certificate:'
                if ($innerMessage.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                  $innerMessage = $innerMessage.Substring($prefix.Length)
                }
                $innerMessage = $innerMessage.Trim()
              }
              $errorMessage = if ([string]::IsNullOrWhiteSpace($innerMessage)) {
                "Failed to decrypt secret with certificate ($certificateIdentifier)."
              }
              else {
                "Failed to decrypt secret with certificate ($certificateIdentifier): $innerMessage"
              }
              throw [System.InvalidOperationException]::new($errorMessage, $_.Exception)
            }
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
