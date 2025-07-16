function Get-SecureStoreSecret {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(ParameterSetName = 'ByName', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(ParameterSetName = 'ByName', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretFileName,

        [Parameter(ParameterSetName = 'ByPath', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyPath,

        [Parameter(ParameterSetName = 'ByPath', Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretPath,

        [Parameter(ParameterSetName = 'ByName', Mandatory = $false)]
        [string]$FolderPath = "C:\SecureStore",

        [Parameter(Mandatory = $false)]
        [switch]$AsCredential
    )

    begin {
        # Import private helper if not already loaded
        if (-not (Get-Command "Sync-SecureStoreWorkingDirectory" -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot\Sync-SecureStoreWorkingDirectory.ps1"
        }
        
        # Sync directories
        Sync-SecureStoreWorkingDirectory | Out-Null
    }

    process {
        try {
            # Determine file paths based on parameter set
            if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
                # Direct path mode - resolve relative paths
                if ([System.IO.Path]::IsPathRooted($KeyPath)) {
                    $keyFilePath = $KeyPath
                } else {
                    $keyFilePath = [System.IO.Path]::Combine((Get-Location).Path, $KeyPath)
                }

                if ([System.IO.Path]::IsPathRooted($SecretPath)) {
                    $secretFilePath = $SecretPath
                } else {
                    $secretFilePath = [System.IO.Path]::Combine((Get-Location).Path, $SecretPath)
                }
            } else {
                # Name-based mode - use SecureStore structure
                $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
                $keyFilePath = [System.IO.Path]::Combine($paths.BinPath, "$KeyName.bin")
                $secretFilePath = [System.IO.Path]::Combine($paths.SecretPath, $SecretFileName)
            }

            # Validate files exist
            if (-not (Test-Path $keyFilePath)) {
                throw "Key file not found: $keyFilePath"
            }

            if (-not (Test-Path $secretFilePath)) {
                throw "Secret file not found: $secretFilePath"
            }

            # Read and decrypt
            $encryptionKey = [System.IO.File]::ReadAllBytes($keyFilePath)
            $encryptedPassword = [System.IO.File]::ReadAllText($secretFilePath, [System.Text.Encoding]::UTF8).Trim()
            $securePassword = ConvertTo-SecureString -String $encryptedPassword -Key $encryptionKey

            # Return based on switch
            if ($AsCredential.IsPresent) {
                return New-Object System.Management.Automation.PSCredential("user", $securePassword)
            } else {
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
                try {
                    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }

        } catch {
            Write-Error "Failed to retrieve secret: $($_.Exception.Message)"
            return $null
        }
    }
}