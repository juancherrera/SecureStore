function New-SecureStoreSecret {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretFileName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [SecureStoreSecureStringTransformation()]
        [System.Security.SecureString]$Password,

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
        $securePassword = $null
        $plaintextBytes = $null
        try {
            $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
            $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

            $keyFilePath = Join-Path -Path $paths.BinPath -ChildPath ("$KeyName.bin")
            $secretFilePath = Join-Path -Path $paths.SecretPath -ChildPath $SecretFileName

            if (-not $PSCmdlet.ShouldProcess($secretFilePath, "Create or update secure secret")) {
                return
            }

            $encryptionKey = $null
            $keyCreated = $false
            if (-not (Test-Path -LiteralPath $keyFilePath)) {
                $encryptionKey = New-Object byte[] 32
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                try {
                    $rng.GetBytes($encryptionKey)
                }
                finally {
                    $rng.Dispose()
                }
                Write-Verbose "Generated new encryption key for '$KeyName'."
                Write-SecureStoreFile -Path $keyFilePath -Bytes $encryptionKey
                $keyCreated = $true
            }

            if (-not $encryptionKey) {
                $encryptionKey = Read-SecureStoreByteArray -Path $keyFilePath
            }

            try {
                $plaintextBytes = Get-SecureStorePlaintextData -SecureString $securePassword
                $payloadJson = Protect-SecureStoreSecret -Plaintext $plaintextBytes -MasterKey $encryptionKey
                $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
                try {
                    Write-SecureStoreFile -Path $secretFilePath -Bytes $payloadBytes
                }
                finally {
                    [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
                }
            }
            finally {
                if ($null -ne $plaintextBytes) {
                    [Array]::Clear($plaintextBytes, 0, $plaintextBytes.Length)
                }
                if ($null -ne $encryptionKey) {
                    [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
                }
            }

            if ($keyCreated) {
                Write-Verbose "Encryption key '$KeyName' stored at '$keyFilePath'."
            }
        }
        catch {
            throw [System.Exception]::new("Failed to create or update secret '$SecretFileName'.", $_.Exception)
        }
        finally {
            if ($securePassword) {
                $securePassword.Dispose()
            }
        }
    }
}
