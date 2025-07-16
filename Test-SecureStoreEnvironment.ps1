function Test-SecureStoreEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$FolderPath = "C:\SecureStore"
    )

    begin {
        if (-not (Get-Command "Sync-SecureStoreWorkingDirectory" -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot\Sync-SecureStoreWorkingDirectory.ps1"
        }
    }

    process {
        Write-Host "SecureStore Environment Test"
        Write-Host "Target base path: $FolderPath"

        # Test directory synchronization
        Write-Host "`nDirectory Synchronization:"
        $before_ps = (Get-Location).Path
        $before_net = [System.IO.Directory]::GetCurrentDirectory()

        Write-Host "  PowerShell location: $before_ps"
        Write-Host "  .NET current directory: $before_net"
        Write-Host "  Synchronized: $(($before_ps -eq $before_net))"

        # Perform sync and get paths
        $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

        # Test SecureStore structure
        Write-Host "`nSecureStore Structure:"
        Write-Host "  Base path: $($paths.BasePath)"
        Write-Host "    Exists: $(Test-Path $paths.BasePath)"

        Write-Host "  Bin folder: $($paths.BinPath)"
        Write-Host "    Exists: $(Test-Path $paths.BinPath)"

        Write-Host "  Secret folder: $($paths.SecretPath)"
        Write-Host "    Exists: $(Test-Path $paths.SecretPath)"

        Write-Host "  Certs folder: $($paths.CertsPath)"
        Write-Host "    Exists: $(Test-Path $paths.CertsPath)"

        # Overall status
        $allGood = (Test-Path $paths.BasePath) -and (Test-Path $paths.BinPath) -and 
                   (Test-Path $paths.SecretPath) -and (Test-Path $paths.CertsPath)

        Write-Host "`nOverall Status: $(if ($allGood) { 'READY' } else { 'NEEDS ATTENTION' })"
    }
}