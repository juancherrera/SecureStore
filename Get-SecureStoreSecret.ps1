function Get-SecureStoreSecret {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType([string])]
    [OutputType([System.Management.Automation.PSCredential])]
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

        [Parameter(ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath = $script:DefaultSecureStorePath,

        [Parameter()]
        [switch]$AsCredential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$UserName = 'user'
    )

    begin {
        if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
        }
    }

    process {
        $encryptionKey = $null
        $plaintextBytes = $null
        $securePassword = $null
        try {
            switch ($PSCmdlet.ParameterSetName) {
                'ByPath' {
                    $keyFilePath = if ([System.IO.Path]::IsPathRooted($KeyPath)) { $KeyPath } else { Join-Path -Path (Get-Location).Path -ChildPath $KeyPath }
                    $secretFilePath = if ([System.IO.Path]::IsPathRooted($SecretPath)) { $SecretPath } else { Join-Path -Path (Get-Location).Path -ChildPath $SecretPath }
                }
                default {
                    $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
                    $keyFilePath = Join-Path -Path $paths.BinPath -ChildPath ("$KeyName.bin")
                    $secretFilePath = Join-Path -Path $paths.SecretPath -ChildPath $SecretFileName
                }
            }

            if (-not (Test-Path -LiteralPath $keyFilePath)) {
                throw [System.IO.FileNotFoundException]::new('The encryption key file could not be located.', $keyFilePath)
            }

            if (-not (Test-Path -LiteralPath $secretFilePath)) {
                throw [System.IO.FileNotFoundException]::new('The secret file could not be located.', $secretFilePath)
            }

            $encryptionKey = Read-SecureStoreByteArray -Path $keyFilePath
            $encryptedPassword = Read-SecureStoreText -Path $secretFilePath -Encoding ([System.Text.Encoding]::UTF8)

            $plaintextBytes = Unprotect-SecureStoreSecret -Payload $encryptedPassword -MasterKey $encryptionKey

            $chars = [System.Text.Encoding]::UTF8.GetChars($plaintextBytes)
            try {
                $securePassword = New-Object System.Security.SecureString
                foreach ($char in $chars) {
                    $securePassword.AppendChar($char)
                }
                $securePassword.MakeReadOnly()
            }
            finally {
                [Array]::Clear($chars, 0, $chars.Length)
            }

            if ($AsCredential.IsPresent) {
                return New-Object System.Management.Automation.PSCredential($UserName, $securePassword.Copy())
            }

            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            try {
                return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        catch {
            throw [System.Exception]::new('Failed to retrieve the requested secret.', $_.Exception)
        }
        finally {
            if ($securePassword) {
                $securePassword.Dispose()
            }
            if ($plaintextBytes) {
                [Array]::Clear($plaintextBytes, 0, $plaintextBytes.Length)
            }
            if ($encryptionKey) {
                [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
            }
        }
    }
}
