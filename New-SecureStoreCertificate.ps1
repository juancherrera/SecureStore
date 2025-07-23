function New-SecureStoreCertificate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [string]$FolderPath = "C:\SecureStore",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50)]
    [int]$ValidityYears = 1,

    [Parameter(Mandatory = $false)]
    [string]$Subject
  )

  begin {
    if (-not (Get-Command "Sync-SecureStoreWorkingDirectory" -ErrorAction SilentlyContinue)) {
      . "$PSScriptRoot\Sync-SecureStoreWorkingDirectory.ps1"
    }
    Sync-SecureStoreWorkingDirectory | Out-Null
  }

  process {
    try {
      # Get SecureStore paths
      $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
          
      # Define certificate paths in certs subfolder
      $certSubject = if ($Subject) { $Subject } else { "CN=$CertificateName" }
      $pfxPath = [System.IO.Path]::Combine($paths.CertsPath, "$CertificateName.pfx")
      $pemPath = [System.IO.Path]::Combine($paths.CertsPath, "$CertificateName.pem")
      $securePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText

      # Check if files already exist
      if ((Test-Path $pfxPath) -or (Test-Path $pemPath)) {
        $response = Read-Host "Certificate files already exist. Overwrite? (y/N)"
        if ($response -notmatch '^[Yy]') {
          Write-Host "Certificate creation cancelled"
          return
        }
      }

      # Create self-signed certificate with EXACT parameters from working code
      $cert = New-SelfSignedCertificate -Subject $certSubject `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotAfter (Get-Date).AddYears($ValidityYears)
      # REMOVED: -NotBefore (Get-Date) to allow default 10-minute backdate

      # Export to PFX with password protection
      Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $securePassword | Out-Null

      # Export to PEM format
      $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      $pemContent = "-----BEGIN CERTIFICATE-----`n" + 
      [Convert]::ToBase64String($certBytes, 'InsertLineBreaks') + 
      "`n-----END CERTIFICATE-----"
      [System.IO.File]::WriteAllText($pemPath, $pemContent, [System.Text.Encoding]::ASCII)

      # Remove certificate from store after export (SecureStore approach)
      Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

      Write-Host "Certificate '$CertificateName' created successfully"
      Write-Host "  PFX: $pfxPath"
      Write-Host "  PEM: $pemPath"
      Write-Host "  Thumbprint: $($cert.Thumbprint)"
      Write-Host "  Valid until: $($cert.NotAfter.ToString('yyyy-MM-dd'))"

    }
    catch {
      Write-Error "Failed to create certificate: $($_.Exception.Message)"
    }
  }
}