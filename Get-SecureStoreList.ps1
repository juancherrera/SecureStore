function Get-SecureStoreList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$FolderPath = "C:\SecureStore"
    )

    begin {
        if (-not (Get-Command "Sync-SecureStoreWorkingDirectory" -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot\Sync-SecureStoreWorkingDirectory.ps1"
        }
        Sync-SecureStoreWorkingDirectory | Out-Null
    }

    process {
        # Get SecureStore paths
        $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

        Write-Host "SecureStore inventory: $($paths.BasePath)"

        # Check keys
        $keyFiles = Get-ChildItem -Path $paths.BinPath -Filter "*.bin" -ErrorAction SilentlyContinue
        Write-Host "Keys ($($keyFiles.Count)):"
        if ($keyFiles) {
            foreach ($key in $keyFiles) {
                Write-Host "  $($key.BaseName)"
            }
        } else {
            Write-Host "  (none)"
        }

        # Check secrets
        $secretFiles = Get-ChildItem -Path $paths.SecretPath -ErrorAction SilentlyContinue
        Write-Host "Secrets ($($secretFiles.Count)):"
        if ($secretFiles) {
            foreach ($secret in $secretFiles) {
                Write-Host "  $($secret.Name)"
            }
        } else {
            Write-Host "  (none)"
        }

        # Check certificates
        $certFiles = Get-ChildItem -Path $paths.CertsPath -Filter "*.*" -ErrorAction SilentlyContinue
        Write-Host "Certificates ($($certFiles.Count)):"
        if ($certFiles) {
            foreach ($cert in $certFiles) {
                Write-Host "  $($cert.Name)"
            }
        } else {
            Write-Host "  (none)"
        }

        # Summary
        $totalFiles = $keyFiles.Count + $secretFiles.Count + $certFiles.Count
        Write-Host "Total assets: $totalFiles"
    }
}