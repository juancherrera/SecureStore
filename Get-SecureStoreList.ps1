function Get-SecureStoreList {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath = $script:DefaultSecureStorePath,

        [Parameter()]
        [ValidateRange(1, 365)]
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
        $secretFiles = @(Get-ChildItem -LiteralPath $paths.SecretPath -File -ErrorAction SilentlyContinue)
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
                        Write-Warning "Certificate '$($file.Name)' expires on $($certificate.NotAfter.ToString('u'))."
                    }
                }
            }
            catch {
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
