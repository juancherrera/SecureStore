<#
.SYNOPSIS
Creates or updates an encrypted secret in the SecureStore repository.

.DESCRIPTION
New-SecureStoreSecret derives or reuses an encryption key, protects the supplied secret
with authenticated AES encryption, and writes the payload using atomic file operations.
It honours ShouldProcess so you can preview writes with -WhatIf or require confirmation.

.PARAMETER KeyName
Logical name used to store the master encryption key (.bin file).

.PARAMETER SecretFileName
Name of the encrypted payload file stored beneath the secrets directory.

.PARAMETER Password
Secret value to protect. Accepts plain text or SecureString and is converted securely.

.PARAMETER FolderPath
Optional custom SecureStore base path. Defaults to the platform-specific root.

.INPUTS
System.String, System.Security.SecureString. Accepts pipeline input for -Password via property name.

.OUTPUTS
None. Writes files and emits verbose information.

.EXAMPLE
New-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' -Password 'P@ssw0rd!'

Creates or updates the secret named prod.secret using the Database master key.

.EXAMPLE
$secure = Read-Host 'Enter API token' -AsSecureString
New-SecureStoreSecret -KeyName 'Api' -SecretFileName 'token.secret' -Password $secure -Confirm:$false

Stores a SecureString value without prompting for confirmation.

.NOTES
Secrets are never written in plain text; in-memory buffers are cleared after use.

.LINK
Get-SecureStoreSecret
#>
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
        [SecureStoreSecureStringTransformationAttribute()]
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
            # Normalise the password input and resolve the SecureStore folder layout up front.
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
                # Generate a random 256-bit key when none exists so the secret is uniquely protected.
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
                # Reuse the existing key; this keeps reads and writes consistent for the same logical secret.
                $encryptionKey = Read-SecureStoreByteArray -Path $keyFilePath
            }

            try {
                # Convert the SecureString into bytes only for the duration of the encryption operation.
                $plaintextBytes = Get-SecureStorePlaintextData -SecureString $securePassword
                $payloadJson = Protect-SecureStoreSecret -Plaintext $plaintextBytes -MasterKey $encryptionKey
                $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
                try {
                    # Atomic write prevents partially written secrets when the process stops unexpectedly.
                    Write-SecureStoreFile -Path $secretFilePath -Bytes $payloadBytes
                }
                finally {
                    [Array]::Clear($payloadBytes, 0, $payloadBytes.Length)
                }
            }
            finally {
                if ($null -ne $plaintextBytes) {
                    # Ensure plaintext remnants do not survive in memory after the write.
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
            throw [System.InvalidOperationException]::new("Failed to create or update secret '$SecretFileName'.", $_.Exception)
        }
        finally {
            if ($securePassword) {
                $securePassword.Dispose()
            }
        }
    }
}
