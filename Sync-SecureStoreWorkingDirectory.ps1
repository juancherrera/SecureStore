function Sync-SecureStoreWorkingDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BasePath = "C:\SecureStore"
    )
    
    # Sync PowerShell and .NET directories
    $psLocation = (Get-Location).Path
    $netLocation = [System.IO.Directory]::GetCurrentDirectory()
    
    if ($psLocation -ne $netLocation) {
        Write-Verbose "Syncing .NET directory from '$netLocation' to '$psLocation'"
        [System.IO.Directory]::SetCurrentDirectory($psLocation)
    }
    
    # Ensure base path is absolute
    $resolvedBasePath = [System.IO.Path]::GetFullPath($BasePath)
    
    # Create SecureStore folder structure
    $binDir = [System.IO.Path]::Combine($resolvedBasePath, "bin")
    $secretDir = [System.IO.Path]::Combine($resolvedBasePath, "secrets")
    $certsDir = [System.IO.Path]::Combine($resolvedBasePath, "certs")
    
    foreach ($dir in @($resolvedBasePath, $binDir, $secretDir, $certsDir)) {
        if (-not (Test-Path $dir)) {
            Write-Verbose "Creating directory: $dir"
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    return @{
        BasePath = $resolvedBasePath
        BinPath = $binDir
        SecretPath = $secretDir
        CertsPath = $certsDir
    }
}