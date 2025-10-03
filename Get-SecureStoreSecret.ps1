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
            $secretCandidates = New-Object System.Collections.Generic.List[string]
            $seenCandidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $addCandidate = {
                param([string]$Candidate)

                if ([string]::IsNullOrWhiteSpace($Candidate)) {
                    return
                }

                $resolvedCandidate = [System.IO.Path]::GetFullPath($Candidate)
                if ($seenCandidates.Add($resolvedCandidate)) {
                    [void]$secretCandidates.Add($resolvedCandidate)
                }
            }

            switch ($PSCmdlet.ParameterSetName) {
                'ByPath' {
                    $keyFilePath = Resolve-SecureStorePath -Path $KeyPath -BasePath (Get-Location).Path
                    $explicitSecretPath = Resolve-SecureStorePath -Path $SecretPath -BasePath (Get-Location).Path
                    & $addCandidate $explicitSecretPath

                    $secretDirectory = Split-Path -Path $explicitSecretPath -Parent
                    if ($secretDirectory) {
                        $leaf = Split-Path -Path $secretDirectory -Leaf
                        if ($leaf -and $leaf.Equals('secret', [System.StringComparison]::OrdinalIgnoreCase)) {
                            $preferredDirectory = Join-Path -Path (Split-Path -Path $secretDirectory -Parent) -ChildPath 'secrets'
                            $preferredFromExplicit = Join-Path -Path $preferredDirectory -ChildPath (Split-Path -Path $explicitSecretPath -Leaf)
                            & $addCandidate $preferredFromExplicit
                        }
                    }
                }
                default {
                    $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath

                    if (Test-SecureStorePathLike -Value $KeyName) {
                        $keyFilePath = Resolve-SecureStorePath -Path $KeyName -BasePath $paths.BasePath
                    }
                    else {
                        $keyChild = if ($KeyName.EndsWith('.bin', [System.StringComparison]::OrdinalIgnoreCase)) { $KeyName } else { "$KeyName.bin" }
                        $keyFilePath = Join-Path -Path $paths.BinPath -ChildPath $keyChild
                    }

                    if (Test-SecureStorePathLike -Value $SecretFileName) {
                        $explicitSecretPath = Resolve-SecureStorePath -Path $SecretFileName -BasePath $paths.BasePath
                        $preferredSecretPath = ConvertTo-SecureStorePreferredSecretPath -Path $explicitSecretPath -PreferredSecretDir $paths.SecretPath -LegacySecretDir $paths.LegacySecretPath
                        & $addCandidate $preferredSecretPath
                        & $addCandidate $explicitSecretPath

                        if ($paths.LegacySecretPath) {
                            $relativeSecretPath = Get-SecureStoreRelativePath -BasePath $paths.SecretPath -TargetPath $preferredSecretPath
                            if ($null -ne $relativeSecretPath) {
                                $legacyCandidate = if ([string]::IsNullOrWhiteSpace($relativeSecretPath)) { $paths.LegacySecretPath } else { Join-Path -Path $paths.LegacySecretPath -ChildPath $relativeSecretPath }
                                & $addCandidate $legacyCandidate
                            }
                        }
                    }
                    else {
                        $preferredSecretPath = Join-Path -Path $paths.SecretPath -ChildPath $SecretFileName
                        & $addCandidate $preferredSecretPath

                        if ($paths.LegacySecretPath) {
                            $legacyCandidate = Join-Path -Path $paths.LegacySecretPath -ChildPath $SecretFileName
                            & $addCandidate $legacyCandidate
                        }
                    }
                }
            }

            if (-not (Test-Path -LiteralPath $keyFilePath)) {
                throw [System.IO.FileNotFoundException]::new('The encryption key file could not be located.', $keyFilePath)
            }

            $secretFilePath = $null
            foreach ($candidate in $secretCandidates) {
                if (Test-Path -LiteralPath $candidate) {
                    $secretFilePath = $candidate
                    break
                }
            }

            if (-not $secretFilePath) {
                $fallbackTarget = if ($secretCandidates.Count -gt 0) { $secretCandidates[0] } else { $SecretFileName }
                throw [System.IO.FileNotFoundException]::new('The secret file could not be located.', $fallbackTarget)
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
