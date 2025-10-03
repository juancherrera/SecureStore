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
    # Ensure helper functions are loaded even when the module is dot‑sourced.
    if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
      . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
    }
  }

  process {
    $securePassword = $null
    $certificate = $null
    $pfxPath = $null
    $pemPath = $null

    try {
      # Convert the supplied password to SecureString and validate it.
      $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
      if ($securePassword.Length -le 0) {
        throw [System.ArgumentException]::new('Certificate password cannot be empty.')
      }

      # Establish output paths if we are exporting to disk.
      if (-not $StoreOnly.IsPresent) {
        $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
        $pfxPath = Join-Path -Path $paths.CertsPath -ChildPath ("$CertificateName.pfx")
        $pemPath = Join-Path -Path $paths.CertsPath -ChildPath ("$CertificateName.pem")
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

      # Create the certificate.  Retry without custom extensions on PS5 if ECDSA fails.
      try {
        $certificate = New-SelfSignedCertificate @certificateParams
      }
      catch {
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

      # Export or keep in store.
      if ($StoreOnly.IsPresent) {
        Write-Verbose "Certificate '$CertificateName' created in Cert:\CurrentUser\My\$($certificate.Thumbprint)"
      }
      else {
        # Export PFX to temporary file and move it atomically.
        $tempPfxPath = "$pfxPath.tmp"
        if (Test-Path -LiteralPath $tempPfxPath) {
          Remove-Item -LiteralPath $tempPfxPath -Force
        }
        try {
          Export-PfxCertificate -Cert $certificate -FilePath $tempPfxPath -Password $securePassword | Out-Null
          Move-Item -LiteralPath $tempPfxPath -Destination $pfxPath -Force

          # Optionally export PEM.
          if ($ExportPem.IsPresent) {
            # Convert SecureString password to plain text.
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            $plainPassword = $null
            try {
              $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
              # Re-import PFX with exportable private key.
              $pfxCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $pfxPath,
                $plainPassword,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
              )
              try {
                # Export certificate portion.
                $certBytes = $pfxCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                $certBase64 = [System.Convert]::ToBase64String($certBytes)
                # Wrap at 64 chars per line.
                $certLines = [System.Text.RegularExpressions.Regex]::Matches($certBase64, '.{1,64}') | ForEach-Object { $_.Value }
                $certPem = "-----BEGIN CERTIFICATE-----`n" + ($certLines -join "`n") + "`n-----END CERTIFICATE-----"

                # Export private key if PS7+.
                $keyPem = $null
                $keyExported = $false
                if ($PSVersionTable.PSVersion.Major -ge 7) {
                  try {
                    if ($Algorithm -eq 'RSA') {
                      $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfxCert)
                      if ($key) {
                        $keyBytes = $key.ExportRSAPrivateKey()
                        $keyBase64 = [System.Convert]::ToBase64String($keyBytes)
                        $keyLines = [System.Text.RegularExpressions.Regex]::Matches($keyBase64, '.{1,64}') | ForEach-Object { $_.Value }
                        $keyPem = "`n-----BEGIN RSA PRIVATE KEY-----`n" + ($keyLines -join "`n") + "`n-----END RSA PRIVATE KEY-----"
                        [Array]::Clear($keyBytes, 0, $keyBytes.Length)
                        $keyExported = $true
                      }
                    }
                    else {
                      $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($pfxCert)
                      if ($key) {
                        $keyBytes = $key.ExportECPrivateKey()
                        $keyBase64 = [System.Convert]::ToBase64String($keyBytes)
                        $keyLines = [System.Text.RegularExpressions.Regex]::Matches($keyBase64, '.{1,64}') | ForEach-Object { $_.Value }
                        $keyPem = "`n-----BEGIN EC PRIVATE KEY-----`n" + ($keyLines -join "`n") + "`n-----END EC PRIVATE KEY-----"
                        [Array]::Clear($keyBytes, 0, $keyBytes.Length)
                        $keyExported = $true
                      }
                    }
                  }
                  catch {
                    Write-Warning "Failed to export private key: $($_.Exception.Message)"
                  }
                }
                if (-not $keyExported) {
                  Write-Warning "PEM export: Certificate only (no private key). Private key export requires PowerShell 7+. Use PFX for full functionality or convert with OpenSSL."
                }

                # Write PEM file.
                $pemContent = if ($keyPem) { $certPem + $keyPem } else { $certPem }
                [System.IO.File]::WriteAllText($pemPath, $pemContent, [System.Text.Encoding]::ASCII)
                [Array]::Clear($certBytes, 0, $certBytes.Length)
              }
              finally {
                $pfxCert.Dispose()
              }
            }
            finally {
              [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
              if ($plainPassword) {
                $chars = $plainPassword.ToCharArray()
                [Array]::Clear($chars, 0, $chars.Length)
              }
            }
          }
        }
        finally {
          if (Test-Path -LiteralPath $tempPfxPath) {
            Remove-Item -LiteralPath $tempPfxPath -Force
          }
        }

        # Remove the certificate from the store after exporting.
        try {
          Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -ErrorAction SilentlyContinue
        }
        catch {
          Write-Verbose "Failed to remove certificate '$($certificate.Thumbprint)' from store: $($_.Exception.Message)"
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
      if ($securePassword) {
        $securePassword.Dispose()
      }
      if ($certificate -and ($certificate -is [System.IDisposable]) -and -not $StoreOnly.IsPresent) {
        $certificate.Dispose()
      }
    }
  }
}
