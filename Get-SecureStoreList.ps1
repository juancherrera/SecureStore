<#
.SYNOPSIS
Summarises keys, secrets, and certificates stored in SecureStore.

.DESCRIPTION
Get-SecureStoreList enumerates the SecureStore folder structure, returning a PSCustomObject
with arrays of key files, secret files, and certificate metadata. Certificates nearing expiry
trigger warnings to aid proactive renewal.

.PARAMETER FolderPath
Optional SecureStore base path. Defaults to the module's standard location.

.PARAMETER ExpiryWarningDays
Number of days before expiry that certificates should be flagged.

.INPUTS
None.

.OUTPUTS
PSCustomObject describing inventory and certificate health.

.EXAMPLE
Get-SecureStoreList

Lists the SecureStore contents using the default path.

.EXAMPLE
Get-SecureStoreList -FolderPath '/srv/app/secrets' -ExpiryWarningDays 45

Lists assets from a custom location and warns about certificates expiring within 45 days.

.NOTES
Only metadata is returned; secret values remain encrypted on disk.

.LINK
New-SecureStoreSecret
#>
function Get-SecureStoreList {
  [CmdletBinding()]
  [OutputType([pscustomobject])]
  param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$FolderPath = $script:DefaultSecureStorePath,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$ExpiryWarningDays = 30
  )

  begin {
    if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
      . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
    }
  }

  process {
    $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

    $keyFiles = @(Get-ChildItem -LiteralPath $paths.BinPath -Filter '*.bin' -File -ErrorAction SilentlyContinue)
    $secretFiles = @()
    $secretFiles += Get-ChildItem -LiteralPath $paths.SecretPath -File -ErrorAction SilentlyContinue

    if ($paths.LegacySecretPath -and (Test-Path -LiteralPath $paths.LegacySecretPath)) {
      $secretFiles += Get-ChildItem -LiteralPath $paths.LegacySecretPath -File -ErrorAction SilentlyContinue
    }

    if ($secretFiles.Count -gt 0) {
      $secretFiles = @($secretFiles | Group-Object -Property Name | ForEach-Object { $_.Group[0] })
    }
    $certFiles = @(Get-ChildItem -LiteralPath $paths.CertsPath -File -ErrorAction SilentlyContinue)

    $certificateDetails = @()
    foreach ($file in $certFiles) {
      $entry = [PSCustomObject]@{
        Name        = $file.Name
        FullName    = $file.FullName
        Thumbprint  = $null
        NotAfter    = $null
        ExpiresSoon = $false
      }

      $certificate = $null
      try {
        switch ($file.Extension.ToLowerInvariant()) {
          '.pem' {
            # PEM files contain base64 encoded DER blocks; strip headers before conversion.
            $content = Read-SecureStoreText -Path $file.FullName -Encoding ([System.Text.Encoding]::ASCII)
            $base64 = ($content -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s', '')
            if (-not [string]::IsNullOrWhiteSpace($base64)) {
              $raw = [Convert]::FromBase64String($base64)
              $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($raw)
            }
          }
          '.cer' { $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file.FullName) }
          '.crt' { $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file.FullName) }
          '.der' { $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file.FullName) }
          default { }
        }

        if ($certificate) {
          $entry.Thumbprint = $certificate.Thumbprint
          $entry.NotAfter = $certificate.NotAfter
          if ($certificate.NotAfter -le (Get-Date).AddDays($ExpiryWarningDays)) {
            $entry.ExpiresSoon = $true
            # Use warnings instead of errors so automation can continue while highlighting risk.
            Write-Warning "Certificate '$($file.Name)' expires on $($certificate.NotAfter.ToString('u'))."
          }
        }
      }
      catch {
        # Verbose output avoids leaking certificate content while still exposing diagnostics.
        Write-Verbose "Failed to parse certificate '$($file.FullName)': $($_.Exception.Message)"
      }
      finally {
        if ($certificate -and ($certificate -is [System.IDisposable])) {
          $certificate.Dispose()
        }
      }

      $certificateDetails += $entry
    }

    [PSCustomObject]@{
      BasePath     = $paths.BasePath
      Keys         = $keyFiles.Name
      Secrets      = $secretFiles.Name
      Certificates = $certificateDetails
    }
  }
}
