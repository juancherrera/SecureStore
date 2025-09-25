<#
.SYNOPSIS
Retrieves a stored SecureStore secret as plain text or PSCredential.

.DESCRIPTION
Get-SecureStoreSecret locates the associated encryption key and secret payload by logical name
or explicit paths, decrypts the payload while enforcing integrity checks, and returns either a
plain text string or PSCredential. Sensitive buffers are zeroed once the value is materialised.

.PARAMETER KeyName
Logical key identifier when using the default folder layout.

.PARAMETER SecretFileName
Secret file name beneath the SecureStore secrets directory.

.PARAMETER KeyPath
Direct path to a .bin key file when bypassing the default layout.

.PARAMETER SecretPath
Direct path to an encrypted secret file when bypassing the default layout.

.PARAMETER FolderPath
Base path of the SecureStore repository. Defaults to the platform-specific location.

.PARAMETER AsCredential
Return the secret as a PSCredential instance instead of plain text.

.PARAMETER UserName
Username associated with the PSCredential output. Ignored unless -AsCredential is specified.

.INPUTS
None. Values are supplied through parameters only.

.OUTPUTS
System.String, System.Management.Automation.PSCredential.

.EXAMPLE
Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret'

Returns the decrypted secret as plain text using the default folder layout.

.EXAMPLE
Get-SecureStoreSecret -KeyPath './bin/Api.bin' -SecretPath './secrets/api.secret' -AsCredential -UserName 'api-user'

Retrieves the secret using explicit file paths and returns a PSCredential.

.NOTES
Decryption throws a friendly error if integrity checks fail or files are missing.

.LINK
New-SecureStoreSecret
#>
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
                    # Allow callers to provide explicit file paths for integration scenarios.
                    $keyFilePath = if ([System.IO.Path]::IsPathRooted($KeyPath)) { $KeyPath } else { Join-Path -Path (Get-Location).Path -ChildPath $KeyPath }
                    $secretFilePath = if ([System.IO.Path]::IsPathRooted($SecretPath)) { $SecretPath } else { Join-Path -Path (Get-Location).Path -ChildPath $SecretPath }
                }
                default {
                    # Resolve the default layout (bin/secrets) when referencing secrets by name.
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

            # Load the key and encrypted payload into memory for decryption.
            $encryptionKey = Read-SecureStoreByteArray -Path $keyFilePath
            $encryptedPassword = Read-SecureStoreText -Path $secretFilePath -Encoding ([System.Text.Encoding]::UTF8)

            $plaintextBytes = Unprotect-SecureStoreSecret -Payload $encryptedPassword -MasterKey $encryptionKey

            $chars = [System.Text.Encoding]::UTF8.GetChars($plaintextBytes)
            try {
                # Reconstruct a SecureString to avoid exposing the password longer than necessary.
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
                # Return a copy so the caller can dispose the credential without affecting internal buffers.
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
            throw [System.InvalidOperationException]::new('Failed to retrieve the requested secret.', $_.Exception)
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
