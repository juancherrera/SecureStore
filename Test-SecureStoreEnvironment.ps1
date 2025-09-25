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

        $status | Add-Member -NotePropertyName 'Ready' -NotePropertyValue ($status.Paths.BaseExists -and $status.Paths.BinExists -and $status.Paths.SecretExists -and $status.Paths.CertsExists) -Force

        return $status
    }
}
