<#
.SYNOPSIS
Creates a password-protected self-signed certificate within SecureStore.

.DESCRIPTION
New-SecureStoreCertificate provisions RSA or ECDSA self-signed certificates, exporting a
PFX protected by the supplied password and optionally a PEM. It supports SAN and EKU entries,
ensures atomic writes, and can store certificates in the Windows certificate store.

.PARAMETER CertificateName
Logical name used for the output PFX/PEM files or certificate friendly name.

.PARAMETER Password
Password protecting the exported PFX. Accepts plain text or SecureString.

.PARAMETER FolderPath
Base SecureStore path containing the certs directory. Defaults to the module's standard path.

.PARAMETER ValidityYears
Number of years the certificate remains valid.

.PARAMETER Subject
Optional X.500 subject name. Defaults to CN=<CertificateName> when omitted.

.PARAMETER Algorithm
Certificate key algorithm. Supports RSA or ECDSA.

.PARAMETER KeyLength
RSA key length in bits. Ignored for ECDSA certificates.

.PARAMETER CurveName
ECDSA curve name. Ignored for RSA certificates.

.PARAMETER DnsName
Optional DNS subject alternative names.

.PARAMETER IpAddress
Optional IP subject alternative names.

.PARAMETER Email
Optional email subject alternative names.

.PARAMETER Uri
Optional URI subject alternative names.

.PARAMETER EnhancedKeyUsage
Optional EKU list to embed within the certificate.

.PARAMETER ExportPem
Switch to export a PEM copy alongside the PFX.

.PARAMETER StoreOnly
Switch to keep certificate in the Windows certificate store without exporting files.

.INPUTS
System.String, System.Security.SecureString for the Password parameter.

.OUTPUTS
PSCustomObject with certificate metadata and file paths.

.EXAMPLE
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -ExportPem

Creates an RSA certificate stored as WebApp.pfx and WebApp.pem.

.EXAMPLE
New-SecureStoreCertificate -CertificateName 'Api' -Password 'Pass123' -StoreOnly

Creates a certificate and keeps it in Cert:\CurrentUser\My without exporting files.

.NOTES
PFX export requires a password. PEM export with private key requires PowerShell 7+ or OpenSSL.

.LINK
Get-SecureStoreList
#>

function Invoke-SecureStoreSelfSignedCertificate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Subject,

    [Parameter(Mandatory = $true)]
    [string]$CertificateName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('RSA', 'ECDSA')]
    [string]$Algorithm,

    [Parameter(Mandatory = $true)]
    [int]$ValidityYears,

    [Parameter()]
    [int]$KeyLength,

    [Parameter()]
    [string]$CurveName,

    [Parameter()]
    [string[]]$DnsName,

    [Parameter()]
    [string[]]$IpAddress,

    [Parameter()]
    [string[]]$Email,

    [Parameter()]
    [string[]]$Uri,

    [Parameter()]
    [string[]]$EnhancedKeyUsage
  )

  # Construct the subject and create a certificate request backed by RSA or ECDSA.
  $distinguishedName = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($Subject)
  $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256

  $key = $null
  try {
    if ($Algorithm -eq 'RSA') {
      $effectiveKeyLength = if ($KeyLength) { $KeyLength } else { 3072 }
      $key = [System.Security.Cryptography.RSA]::Create($effectiveKeyLength)
      $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $distinguishedName,
        $key,
        $hashAlgorithm,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
      )
    }
    else {
      try {
        $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($CurveName)
      }
      catch {
        throw [System.ArgumentException]::new("Unsupported curve '$CurveName'.")
      }
      $key = [System.Security.Cryptography.ECDsa]::Create($curve)
      $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $distinguishedName,
        $key,
        $hashAlgorithm
      )
    }

    # Basic constraints ensure the certificate is marked for end-entity usage.
    $request.CertificateExtensions.Add(
      [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false)
    )

    # Key usage flags mirror New-SelfSignedCertificate defaults for TLS server auth.
    $keyUsageFlags = if ($Algorithm -eq 'RSA') {
      [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    }
    else {
      [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
    }
    $request.CertificateExtensions.Add(
      [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($keyUsageFlags, $false)
    )

    # Subject alternative names.
    if ($DnsName -or $IpAddress -or $Email -or $Uri) {
      $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
      foreach ($value in ($DnsName | Where-Object { $_ })) { $sanBuilder.AddDnsName($value) }
      foreach ($value in ($IpAddress | Where-Object { $_ })) { $sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse($value)) }
      foreach ($value in ($Email | Where-Object { $_ })) { $sanBuilder.AddEmailAddress($value) }
      foreach ($value in ($Uri | Where-Object { $_ })) { $sanBuilder.AddUri([System.Uri]::new($value)) }
      $request.CertificateExtensions.Add($sanBuilder.Build())
    }

    if ($EnhancedKeyUsage -and $EnhancedKeyUsage.Count -gt 0) {
      $oids = New-Object System.Security.Cryptography.OidCollection
      foreach ($oidValue in $EnhancedKeyUsage) {
        if (-not [string]::IsNullOrWhiteSpace($oidValue)) {
          [void]$oids.Add([System.Security.Cryptography.Oid]::new($oidValue))
        }
      }
      if ($oids.Count -gt 0) {
        $request.CertificateExtensions.Add(
          [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false)
        )
      }
    }

    $notBefore = [System.DateTimeOffset]::UtcNow.AddMinutes(-5)
    $notAfter = $notBefore.AddYears($ValidityYears)
    $certificate = $request.CreateSelfSigned($notBefore, $notAfter)
    try {
      $certificate.FriendlyName = $CertificateName
    }
    catch [System.PlatformNotSupportedException] {
      Write-Verbose "FriendlyName not supported on this platform."
    }
    return $certificate
  }
  finally {
    if ($key -is [System.IDisposable]) {
      $key.Dispose()
    }
  }
}

function New-SecureStoreCertificate {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Export')]
  [OutputType([pscustomobject])]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [object]$Password,

    [Parameter(ParameterSetName = 'Export')]
    [ValidateNotNullOrEmpty()]
    [string]$FolderPath = $script:DefaultSecureStorePath,

    [Parameter()]
    [ValidateRange(1, 50)]
    [int]$ValidityYears = 1,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Subject,

    [Parameter()]
    [ValidateSet('RSA', 'ECDSA')]
    [string]$Algorithm = 'RSA',

    [Parameter()]
    [ValidateRange(256, 8192)]
    [int]$KeyLength,

    [Parameter()]
    [ValidateSet('nistP256', 'nistP384', 'nistP521')]
    [string]$CurveName,

    [Parameter()]
    [string[]]$DnsName,

    [Parameter()]
    [string[]]$IpAddress,

    [Parameter()]
    [string[]]$Email,

    [Parameter()]
    [string[]]$Uri,

    [Parameter()]
    [string[]]$EnhancedKeyUsage = @('1.3.6.1.5.5.7.3.1'),

    [Parameter(ParameterSetName = 'Export')]
    [switch]$ExportPem,

    [Parameter(ParameterSetName = 'StoreOnly')]
    [switch]$StoreOnly
  )

  begin {
    if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
      . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
    }
  }

  process {
    $securePassword = $null
    $certificate = $null
    $pfxPath = $null
    $pemPath = $null
    $selfSignedCommand = Get-Command -Name 'New-SelfSignedCertificate' -ErrorAction SilentlyContinue

    try {
      # Convert the supplied password to SecureString and validate it.
      $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
      if ($securePassword.Length -le 0) {
        throw [System.ArgumentException]::new('Certificate password cannot be empty.')
      }

      # Establish output paths if we are exporting to disk.
      if (-not $StoreOnly.IsPresent) {
        $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
        $pfxPath = [string](Join-Path -Path $paths.CertsPath -ChildPath ("$CertificateName.pfx"))
        $pemPath = [string](Join-Path -Path $paths.CertsPath -ChildPath ("$CertificateName.pem"))
        if (-not $PSCmdlet.ShouldProcess($pfxPath, "Create certificate '$CertificateName'")) {
          return
        }
      }
      else {
        if (-not $PSCmdlet.ShouldProcess("Cert:\CurrentUser\My", "Create certificate '$CertificateName'")) {
          return
        }
      }

      # Build the subject. Default to CN=<CertificateName>.
      $subjectName = if ($Subject) { $Subject } else { "CN=$CertificateName" }

      # Validate mutually exclusive parameters based on algorithm.
      if ($Algorithm -eq 'RSA') {
        if (-not $PSBoundParameters.ContainsKey('KeyLength')) {
          $KeyLength = 3072
        }
        if ($PSBoundParameters.ContainsKey('CurveName')) {
          throw [System.ArgumentException]::new('CurveName is only applicable when Algorithm is ECDSA.')
        }
      }
      else {
        if ($PSBoundParameters.ContainsKey('KeyLength')) {
          throw [System.ArgumentException]::new('KeyLength is only applicable when Algorithm is RSA.')
        }
        if (-not $PSBoundParameters.ContainsKey('CurveName')) {
          $CurveName = 'nistP256'
        }
      }

      # Build SAN and EKU text extensions.
      $textExtensions = @()
      $sanComponents = @()
      if ($DnsName) { $sanComponents += ($DnsName   | ForEach-Object { "dns=$_" }) }
      if ($IpAddress) { $sanComponents += ($IpAddress | ForEach-Object { "ipaddress=$_" }) }
      if ($Email) { $sanComponents += ($Email     | ForEach-Object { "email=$_" }) }
      if ($Uri) { $sanComponents += ($Uri       | ForEach-Object { "url=$_" }) }
      if ($sanComponents.Count -gt 0) {
        $textExtensions += "2.5.29.17={text}$($sanComponents -join '&')"
      }
      if ($EnhancedKeyUsage -and $EnhancedKeyUsage.Count -gt 0) {
        $textExtensions += "2.5.29.37={text}$($EnhancedKeyUsage -join ',')"
      }

      # Base certificate parameters.
      $certificateParams = @{
        Subject           = $subjectName
        CertStoreLocation = 'Cert:\CurrentUser\My'
        NotAfter          = (Get-Date).AddYears($ValidityYears)
        KeyExportPolicy   = 'Exportable'
        KeySpec           = 'Signature'
        HashAlgorithm     = 'SHA256'
        FriendlyName      = $CertificateName
      }

      # On Windows, explicitly set the provider for RSA keys.
      if ($Algorithm -eq 'RSA' -and $script:IsWindowsPlatform) {
        $certificateParams['Provider'] = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
      }

      # Algorithm-specific parameters.
      if ($Algorithm -eq 'RSA') {
        $certificateParams['KeyAlgorithm'] = 'RSA'
        $certificateParams['KeyLength'] = $KeyLength
      }
      else {
        # ECDSA parameters depend on the PowerShell version:
        # - PS7+: use KeyAlgorithm='ECDSA' and separate CurveName.
        # - PS5.1: embed the curve in the algorithm name (e.g. ECDSA_nistP256).
        if ($PSVersionTable.PSVersion.Major -ge 7) {
          $certificateParams['KeyAlgorithm'] = 'ECDSA'
          $certificateParams['CurveName'] = $CurveName
        }
        else {
          $certificateParams['KeyAlgorithm'] = "ECDSA_$CurveName"
        }
      }

      # Add custom extensions if present.
      if ($textExtensions.Count -gt 0) {
        $certificateParams['Type'] = 'Custom'
        $certificateParams['TextExtension'] = $textExtensions
      }

      # Create the certificate, falling back to pure .NET APIs when the cmdlet is unavailable.
      if ($selfSignedCommand) {
        try {
          $certificate = New-SelfSignedCertificate @certificateParams
        }
        catch {
          # ECDSA with custom extensions can fail on some systems
          if ($Algorithm -eq 'ECDSA' -and ($certificateParams.ContainsKey('Type') -or $certificateParams.ContainsKey('TextExtension'))) {
            Write-Warning "ECDSA with SAN/EKU extensions not supported on this system. Creating basic ECDSA certificate."
            $certificateParams.Remove('Type')
            $certificateParams.Remove('TextExtension')
            $certificate = New-SelfSignedCertificate @certificateParams
          }
          else {
            throw
          }
        }
      }
      else {
        $certificate = Invoke-SecureStoreSelfSignedCertificate -Subject $subjectName -CertificateName $CertificateName -Algorithm $Algorithm -ValidityYears $ValidityYears -KeyLength $KeyLength -CurveName $CurveName -DnsName $DnsName -IpAddress $IpAddress -Email $Email -Uri $Uri -EnhancedKeyUsage $EnhancedKeyUsage
      }

      # Export or keep in store.
      if ($StoreOnly.IsPresent) {
        if (-not $selfSignedCommand) {
          try {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            try {
              $store.Add($certificate)
            }
            finally {
              $store.Close()
            }
          }
          catch {
            Write-Warning "Failed to persist certificate to Cert:\\CurrentUser\\My: $($_.Exception.Message)"
          }
        }
        Write-Verbose "Certificate '$CertificateName' created in Cert:\CurrentUser\My\$($certificate.Thumbprint)"
      }
      else {
        # Export PFX using the helper for atomic writes.
        if (Test-Path -LiteralPath $pfxPath) {
          Remove-Item -LiteralPath $pfxPath -Force
        }
        $pfxBytes = $null
        $plainPassword = $null
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        try {
          $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
          $pfxBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $plainPassword)
          try {
            Write-SecureStoreFile -Path $pfxPath -Bytes $pfxBytes
          }
          finally {
            if ($pfxBytes) {
              [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
            }
          }

          # Optionally export PEM.
          if ($ExportPem.IsPresent) {
            $certBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $certBase64 = [System.Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
            $certPem = "-----BEGIN CERTIFICATE-----`n" + $certBase64 + "`n-----END CERTIFICATE-----"

            # Export private key if PS7+.
            $keyPem = $null
            $keyExported = $false
            if ($PSVersionTable.PSVersion.Major -ge 7) {
              try {
                if ($Algorithm -eq 'RSA') {
                  $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
                  if ($key) {
                    try {
                      $keyBytes = $key.ExportRSAPrivateKey()
                      $keyBase64 = [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
                      $keyPem = "`n-----BEGIN RSA PRIVATE KEY-----`n" + $keyBase64 + "`n-----END RSA PRIVATE KEY-----"
                      [Array]::Clear($keyBytes, 0, $keyBytes.Length)
                      $keyExported = $true
                    }
                    finally {
                      $key.Dispose()
                    }
                  }
                }
                else {
                  $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
                  if ($key) {
                    try {
                      $keyBytes = $key.ExportECPrivateKey()
                      $keyBase64 = [System.Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
                      $keyPem = "`n-----BEGIN EC PRIVATE KEY-----`n" + $keyBase64 + "`n-----END EC PRIVATE KEY-----"
                      [Array]::Clear($keyBytes, 0, $keyBytes.Length)
                      $keyExported = $true
                    }
                    finally {
                      $key.Dispose()
                    }
                  }
                }
              }
              catch {
                Write-Warning "Failed to export private key: $($_.Exception.Message)"
              }
            }
            if (-not $keyExported) {
              Write-Warning "PEM export: Certificate only (no private key). Private key export requires PowerShell 7+. Use PFX for full functionality or convert with OpenSSL."
            }

            # Write PEM file using atomic helper for consistent mocking in tests.
            $pemContent = if ($keyPem) { $certPem + $keyPem } else { $certPem }
            $pemBytes = [System.Text.Encoding]::ASCII.GetBytes($pemContent)
            try {
              Write-SecureStoreFile -Path $pemPath -Bytes $pemBytes
            }
            finally {
              [Array]::Clear($pemBytes, 0, $pemBytes.Length)
              [Array]::Clear($certBytes, 0, $certBytes.Length)
            }
          }
        }
        finally {
          [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
          if ($plainPassword) {
            $chars = $plainPassword.ToCharArray()
            [Array]::Clear($chars, 0, $chars.Length)
          }
        }

        # Remove the certificate from the store after exporting when using the Windows cmdlet workflow.
        if ($selfSignedCommand) {
          try {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
          }
          catch {
            Write-Verbose "Failed to remove certificate '$($certificate.Thumbprint)' from store: $($_.Exception.Message)"
          }
        }
      }

      # Return result object.
      [PSCustomObject]@{
        CertificateName = $CertificateName
        Subject         = $subjectName
        Algorithm       = $Algorithm
        KeyLength       = if ($Algorithm -eq 'RSA') { $KeyLength } else { $null }
        CurveName       = if ($Algorithm -eq 'ECDSA') { $CurveName } else { $null }
        Thumbprint      = $certificate.Thumbprint
        NotAfter        = $certificate.NotAfter
        StoreLocation   = if ($StoreOnly) { "Cert:\CurrentUser\My\$($certificate.Thumbprint)" } else { $null }
        Paths           = if (-not $StoreOnly) {
          [PSCustomObject]@{
            Pfx = $pfxPath
            Pem = if ($ExportPem) { $pemPath } else { $null }
          }
        }
        else { $null }
      }
    }
    catch {
      throw [System.InvalidOperationException]::new("Failed to create certificate '$CertificateName'.", $_.Exception)
    }
    finally {
      # Zeroise sensitive material even when errors occur.
      if ($securePassword) {
        $securePassword.Dispose()
      }
      if ($certificate -and ($certificate -is [System.IDisposable]) -and -not $StoreOnly.IsPresent) {
        $certificate.Dispose()
      }
    }
  }
}