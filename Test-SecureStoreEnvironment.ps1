<#
.SYNOPSIS
Validates the SecureStore working directories and process locations.

.DESCRIPTION
Test-SecureStoreEnvironment checks that the PowerShell and .NET working directories align,
verifies required SecureStore folders exist, and reports an overall readiness flag for troubleshooting.

.PARAMETER FolderPath
Optional SecureStore base path. Defaults to the platform-specific location.

.INPUTS
None.

.OUTPUTS
PSCustomObject containing location and folder readiness information.

.EXAMPLE
Test-SecureStoreEnvironment

Displays readiness information for the default SecureStore location.

.EXAMPLE
Test-SecureStoreEnvironment -FolderPath '/srv/app/secrets'

Checks a custom SecureStore base path often used on Linux deployments.

.NOTES
Use this command to diagnose mismatched working directories or missing folders.

.LINK
Get-SecureStoreList
#>
function Test-SecureStoreEnvironment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath = $script:DefaultSecureStorePath
    )

    begin {
        if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
        }
    }

    process {
        $psLocation = (Get-Location).Path
        $netLocation = [System.IO.Directory]::GetCurrentDirectory()
        $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

        $status = [PSCustomObject]@{
            Locations = [PSCustomObject]@{
                PowerShell = $psLocation
                DotNet     = $netLocation
                # Helpful to highlight when PowerShell and .NET disagree, which can break relative paths.
                InSync     = ($psLocation -eq $netLocation)
            }
            Paths = [PSCustomObject]@{
                BasePath    = $paths.BasePath
                BaseExists  = Test-Path -LiteralPath $paths.BasePath
                BinExists   = Test-Path -LiteralPath $paths.BinPath
                SecretExists = Test-Path -LiteralPath $paths.SecretPath
                CertsExists = Test-Path -LiteralPath $paths.CertsPath
            }
        }

        # Summarise readiness so CI/CD can quickly decide whether to create missing folders.
        $status | Add-Member -NotePropertyName 'Ready' -NotePropertyValue ($status.Paths.BaseExists -and $status.Paths.BinExists -and $status.Paths.SecretExists -and $status.Paths.CertsExists) -Force

        return $status
    }
}
