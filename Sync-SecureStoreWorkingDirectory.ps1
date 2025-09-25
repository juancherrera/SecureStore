function Sync-SecureStoreWorkingDirectory {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$BasePath
    )

    # Sync PowerShell and .NET directories
    $psLocation = (Get-Location).Path
    $netLocation = [System.IO.Directory]::GetCurrentDirectory()

    if ($psLocation -ne $netLocation) {
        Write-Verbose "Syncing .NET directory from '$netLocation' to '$psLocation'"
        [System.IO.Directory]::SetCurrentDirectory($psLocation)
    }

    if (-not $PSBoundParameters.ContainsKey('BasePath') -or [string]::IsNullOrWhiteSpace($BasePath)) {
        $BasePath = Get-SecureStoreDefaultPath
    }

    $resolvedInputPath = [System.IO.Path]::GetFullPath($BasePath)

    $leafName = Split-Path -Path $resolvedInputPath -Leaf
    $resolvedBasePath = $resolvedInputPath
    $secretOverridePath = $null

    if ($leafName -and ($leafName.Equals('secrets', [System.StringComparison]::InvariantCultureIgnoreCase) -or $leafName.Equals('secret', [System.StringComparison]::InvariantCultureIgnoreCase))) {
        $secretOverridePath = $resolvedInputPath
        $parentPath = Split-Path -Path $resolvedInputPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($parentPath)) {
            $resolvedBasePath = $parentPath
        }
    }

    # Create SecureStore folder structure
    $binDir = Join-Path -Path $resolvedBasePath -ChildPath 'bin'
    $preferredSecretDir = if ($secretOverridePath -and $leafName.Equals('secrets', [System.StringComparison]::InvariantCultureIgnoreCase)) {
        $secretOverridePath
    }
    else {
        Join-Path -Path $resolvedBasePath -ChildPath 'secrets'
    }

    $legacySecretDir = if ($secretOverridePath -and $leafName.Equals('secret', [System.StringComparison]::InvariantCultureIgnoreCase)) {
        $secretOverridePath
    }
    else {
        Join-Path -Path $resolvedBasePath -ChildPath 'secret'
    }

    $certsDir = Join-Path -Path $resolvedBasePath -ChildPath 'certs'

    $secretDir = $preferredSecretDir

    if ((Test-Path -LiteralPath $legacySecretDir) -and -not (Test-Path -LiteralPath $preferredSecretDir)) {
        $secretDir = $legacySecretDir
        if (-not $script:LegacySecretWarningIssued) {
            Write-Warning "The 'secret' folder name is deprecated and will be removed in a future major version. Please migrate to 'secrets'."
            $script:LegacySecretWarningIssued = $true
        }
    }

    foreach ($dir in @($resolvedBasePath, $binDir, $preferredSecretDir, $certsDir)) {
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
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
