#
<#
.SYNOPSIS
SecureStore module providing local secret storage and certificate automation helpers.

.DESCRIPTION
The SecureStore module centralizes encrypted secrets and self-signed certificate creation
while standardising folder layout, zeroizing sensitive data, and honouring PowerShell's
ShouldProcess semantics. It ships with helper functions to generate keys, protect secrets,
list inventory, and validate the working environment across Windows PowerShell and PowerShell 7.

.INPUTS
None. Use the exported functions such as New-SecureStoreSecret and Get-SecureStoreList.

.OUTPUTS
Module exports PSCustomObject and string outputs depending on the function invoked.

.EXAMPLE
Import-Module SecureStore
Test-SecureStoreEnvironment | Format-List

.EXAMPLE
Import-Module SecureStore
New-SecureStoreSecret -KeyName 'WebApp' -SecretFileName 'service.secret' -Password 'Sup3r$ecret' -Confirm:$false

.NOTES
Version 2.0 of SecureStore focuses on secure local storage with AES-GCM when available
and AES-CBC with HMAC-SHA256 otherwise.

.LINK
https://github.com/juancherrera/SecureStore
#>
Set-StrictMode -Version Latest

# SecureStore Module v2.0
# Centralized local secret management and certificate generation

$script:IsWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)

function Get-SecureStoreType {
    [CmdletBinding()]
    [OutputType([System.Type])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TypeName
    )

    foreach ($assembly in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
        $type = $assembly.GetType($TypeName, $false, $false)
        if ($null -ne $type) {
            return $type
        }
    }

    return [System.Type]::GetType($TypeName, $false, $false)
}

function Get-SecureStoreDefaultPath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($script:IsWindowsPlatform) {
        $programData = $env:ProgramData
        if ([string]::IsNullOrWhiteSpace($programData)) {
            throw "ProgramData environment variable is not set."
        }

        return [System.IO.Path]::Combine($programData, 'SecureStore')
    }

    $homePath = if (-not [string]::IsNullOrWhiteSpace($env:HOME)) { $env:HOME } else { $HOME }
    if ([string]::IsNullOrWhiteSpace($homePath)) {
        throw "HOME environment variable is not set."
    }

    return Join-Path -Path $homePath -ChildPath '.securestore'
}

$script:DefaultSecureStorePath = Get-SecureStoreDefaultPath
$script:LegacySecretWarningIssued = $false

$script:AesGcmType = Get-SecureStoreType -TypeName 'System.Security.Cryptography.AesGcm'
if (-not $script:AesGcmType) {
    try {
        Add-Type -AssemblyName 'System.Security.Cryptography.Algorithms' -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Verbose "AES-GCM support unavailable: $($_.Exception.Message)"
    }

    $script:AesGcmType = Get-SecureStoreType -TypeName 'System.Security.Cryptography.AesGcm'
}

$script:SupportsAesGcm = $null -ne $script:AesGcmType

function Test-SecureStoreFixedTimeEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Left,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    $result = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $result = $result -bor ($Left[$i] -bxor $Right[$i])
    }

    return ($result -eq 0)
}

function ConvertTo-SecureStoreSecureString {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$InputObject
    )

    switch ($InputObject) {
        { $_ -is [System.Security.SecureString] } {
            return $_.Copy()
        }
        { $_ -is [string] } {
            if ([string]::IsNullOrWhiteSpace([string]$_)) {
                throw [System.ArgumentException]::new('Password cannot be null or empty.')
            }

            $chars = ([string]$_).ToCharArray()
            try {
                $secure = New-Object System.Security.SecureString
                foreach ($char in $chars) {
                    $secure.AppendChar($char)
                }
                $secure.MakeReadOnly()
                return $secure
            }
            finally {
                [Array]::Clear($chars, 0, $chars.Length)
            }
        }
        { $_ -is [System.Collections.IEnumerable] -and -not ($_ -is [string]) } {
            $results = @()
            foreach ($item in $_) {
                $results += ConvertTo-SecureStoreSecureString -InputObject $item
            }

            if ($results.Count -eq 1) {
                return $results[0]
            }

            return $results
        }
        default {
            $message = 'Password must be provided as a SecureString or plain text string.'
            throw [System.ArgumentException]::new($message)
        }
    }
}

function Get-SecureStorePlaintextData {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Security.SecureString]$SecureString
    )

    # Marshal the SecureString into unmanaged memory so it can be converted safely to UTF-8 bytes.
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    if ($bstr -eq [IntPtr]::Zero) {
        throw 'Unable to marshal secure string.'
    }

    try {
        $length = [System.Runtime.InteropServices.Marshal]::ReadInt32($bstr, -4)
        $unicodeBytes = New-Object byte[] $length
        [System.Runtime.InteropServices.Marshal]::Copy($bstr, $unicodeBytes, 0, $length)

        try {
            $chars = New-Object char[] ($length / 2)
            [System.Buffer]::BlockCopy($unicodeBytes, 0, $chars, 0, $length)
            try {
                # Re-encode to UTF-8 so the payload is platform agnostic.
                $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($chars)
                [Array]::Clear($chars, 0, $chars.Length)
                return $utf8Bytes
            }
            finally {
                [Array]::Clear($chars, 0, $chars.Length)
            }
        }
        finally {
            [Array]::Clear($unicodeBytes, 0, $unicodeBytes.Length)
        }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Write-SecureStoreFile {
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Bytes
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrEmpty($directory) -and -not (Test-Path -LiteralPath $directory)) {
        # Create the target directory ahead of time to avoid partial writes later on.
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $tempFile = Join-Path -Path $directory -ChildPath ((New-Guid).Guid + '.tmp')

    $fileStream = [System.IO.FileStream]::new(
        $tempFile,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )

    try {
        # Write through a temporary file so the final rename is atomic even on network shares.
        $fileStream.Write($Bytes, 0, $Bytes.Length)
        $fileStream.Flush($true)
    }
    finally {
        $fileStream.Dispose()
    }

    # Only move after the flush succeeds to avoid corrupting existing files with partial content.
    Move-Item -LiteralPath $tempFile -Destination $Path -Force
}

function Read-SecureStoreByteArray {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    return [System.IO.File]::ReadAllBytes($Path)
}

function Read-SecureStoreText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
    )

    return [System.IO.File]::ReadAllText($Path, $Encoding)
}

function Protect-SecureStoreSecret {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Plaintext,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$MasterKey
    )

    # Generate a fresh salt for PBKDF2 so identical passwords produce different ciphertexts.
    $salt = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($salt)
    }
    finally {
        $rng.Dispose()
    }

    $payload = $null
    if ($script:SupportsAesGcm) {
        # AES-GCM requires a unique nonce per encryption; use 96-bit nonce recommended by the spec.
        $nonce = New-Object byte[] 12
        $tag = New-Object byte[] 16

        $rngForGcm = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rngForGcm.GetBytes($nonce)
        }
        finally {
            $rngForGcm.Dispose()
        }

        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($MasterKey, $salt, 200000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try {
            # Derive a 256-bit key for AES-GCM using high iteration PBKDF2 to resist brute force.
            $derivedKey = $kdf.GetBytes(32)
        }
        finally {
            $kdf.Dispose()
        }

        $ciphertext = New-Object byte[] $Plaintext.Length
        $aes = New-Object -TypeName $script:AesGcmType.FullName -ArgumentList (, $derivedKey)
        try {
            # Encrypt and authenticate in one pass so tampering is detected during decryption.
            $aes.Encrypt($nonce, $Plaintext, $ciphertext, $tag)
        }
        finally {
            if ($aes -is [System.IDisposable]) {
                $aes.Dispose()
            }
            [Array]::Clear($derivedKey, 0, $derivedKey.Length)
        }

        $payload = [ordered]@{
            Version = 2
            KeyDerivation = [ordered]@{
                Algorithm = 'PBKDF2'
                Iterations = 200000
                Hash = 'SHA256'
                Salt = [Convert]::ToBase64String($salt)
            }
            Cipher = [ordered]@{
                Algorithm = 'AES-GCM'
                KeySize = 256
                Nonce = [Convert]::ToBase64String($nonce)
                Tag = [Convert]::ToBase64String($tag)
                CipherText = [Convert]::ToBase64String($ciphertext)
            }
        }

        [Array]::Clear($nonce, 0, $nonce.Length)
        [Array]::Clear($tag, 0, $tag.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
    }
    else {
        # AES-CBC fallback uses a random IV which is later stored alongside the ciphertext.
        $iv = New-Object byte[] 16
        $nonceRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $nonceRng.GetBytes($iv)
        }
        finally {
            $nonceRng.Dispose()
        }

        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($MasterKey, $salt, 200000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try {
            # Derive both encryption and HMAC keys in a single expansion to keep them related yet distinct.
            $derivedKey = $kdf.GetBytes(64)
        }
        finally {
            $kdf.Dispose()
        }

        $encryptionKey = New-Object byte[] 32
        $hmacKey = New-Object byte[] 32
        [System.Buffer]::BlockCopy($derivedKey, 0, $encryptionKey, 0, 32)
        [System.Buffer]::BlockCopy($derivedKey, 32, $hmacKey, 0, 32)
        [Array]::Clear($derivedKey, 0, $derivedKey.Length)

        $aesProvider = [System.Security.Cryptography.Aes]::Create()
        try {
            $aesProvider.KeySize = 256
            $aesProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aesProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aesProvider.Key = $encryptionKey
            $aesProvider.IV = $iv

            $encryptor = $aesProvider.CreateEncryptor()
            try {
            # Encrypt the plaintext in-memory; TransformFinalBlock clears internal buffers afterwards.
            $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
            }
            finally {
                if ($encryptor -is [System.IDisposable]) {
                    $encryptor.Dispose()
                }
            }
        }
        finally {
            if ($aesProvider -is [System.IDisposable]) {
                $aesProvider.Dispose()
            }
            [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
        }

        $hmacProvider = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
        try {
            # HMAC covers IV and ciphertext to protect against modification attacks.
            $macInput = New-Object byte[] ($iv.Length + $ciphertext.Length)
            try {
                [System.Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
                [System.Buffer]::BlockCopy($ciphertext, 0, $macInput, $iv.Length, $ciphertext.Length)
                $tag = $hmacProvider.ComputeHash($macInput)
            }
            finally {
                [Array]::Clear($macInput, 0, $macInput.Length)
            }
        }
        finally {
            $hmacProvider.Dispose()
            [Array]::Clear($hmacKey, 0, $hmacKey.Length)
        }

        $payload = [ordered]@{
            Version = 2
            KeyDerivation = [ordered]@{
                Algorithm = 'PBKDF2'
                Iterations = 200000
                Hash = 'SHA256'
                Salt = [Convert]::ToBase64String($salt)
            }
            Cipher = [ordered]@{
                Algorithm = 'AES-CBC-HMACSHA256'
                KeySize = 256
                IV = [Convert]::ToBase64String($iv)
                Hmac = [Convert]::ToBase64String($tag)
                CipherText = [Convert]::ToBase64String($ciphertext)
            }
        }

        [Array]::Clear($iv, 0, $iv.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        [Array]::Clear($tag, 0, $tag.Length)
    }

    [Array]::Clear($salt, 0, $salt.Length)

    $json = $payload | ConvertTo-Json -Depth 4

    [Array]::Clear($Plaintext, 0, $Plaintext.Length)

    return $json
}

function Unprotect-SecureStoreSecret {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Payload,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$MasterKey
    )

    $data = $Payload | ConvertFrom-Json -ErrorAction Stop

    if ($null -eq $data.Cipher -or $null -eq $data.KeyDerivation) {
        throw 'Secret payload is missing metadata.'
    }

    $salt = [Convert]::FromBase64String([string]$data.KeyDerivation.Salt)

    $iterations = if ($data.KeyDerivation.Iterations) { [int]$data.KeyDerivation.Iterations } else { 200000 }

    $cipherAlgorithm = [string]$data.Cipher.Algorithm

    $plaintext = $null

    if ($cipherAlgorithm -eq 'AES-GCM') {
        if (-not $script:SupportsAesGcm) {
            throw 'Encrypted secret uses AES-GCM but the runtime does not support it.'
        }

        # Nonce, tag, and ciphertext were persisted in base64; decode before verification/decryption.
        $nonce = [Convert]::FromBase64String([string]$data.Cipher.Nonce)
        $tag = [Convert]::FromBase64String([string]$data.Cipher.Tag)
        $ciphertext = [Convert]::FromBase64String([string]$data.Cipher.CipherText)

        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($MasterKey, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try {
            # Derive the same AES-GCM key used during encryption.
            $derivedKey = $kdf.GetBytes(32)
        }
        finally {
            $kdf.Dispose()
        }

        $plaintext = New-Object byte[] $ciphertext.Length
        $aes = New-Object -TypeName $script:AesGcmType.FullName -ArgumentList (, $derivedKey)
        try {
            # Decrypt while validating the authentication tag to detect tampering.
            $aes.Decrypt($nonce, $ciphertext, $tag, $plaintext)
        }
        catch {
            throw 'Secret integrity check failed.'
        }
        finally {
            if ($aes -is [System.IDisposable]) {
                $aes.Dispose()
            }
            [Array]::Clear($derivedKey, 0, $derivedKey.Length)
        }

        [Array]::Clear($nonce, 0, $nonce.Length)
        [Array]::Clear($tag, 0, $tag.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
    }
    elseif ($cipherAlgorithm -eq 'AES-CBC-HMACSHA256') {
        $iv = [Convert]::FromBase64String([string]$data.Cipher.IV)
        $hmac = [Convert]::FromBase64String([string]$data.Cipher.Hmac)
        $ciphertext = [Convert]::FromBase64String([string]$data.Cipher.CipherText)

        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($MasterKey, $salt, $iterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        try {
            $derivedKey = $kdf.GetBytes(64)
        }
        finally {
            $kdf.Dispose()
        }

        $encryptionKey = New-Object byte[] 32
        $hmacKey = New-Object byte[] 32
        [System.Buffer]::BlockCopy($derivedKey, 0, $encryptionKey, 0, 32)
        [System.Buffer]::BlockCopy($derivedKey, 32, $hmacKey, 0, 32)
        [Array]::Clear($derivedKey, 0, $derivedKey.Length)

        $hmacProvider = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
        try {
            $macInput = New-Object byte[] ($iv.Length + $ciphertext.Length)
            try {
                [System.Buffer]::BlockCopy($iv, 0, $macInput, 0, $iv.Length)
                [System.Buffer]::BlockCopy($ciphertext, 0, $macInput, $iv.Length, $ciphertext.Length)
                # Compute an HMAC over the IV and ciphertext to compare against the stored tag.
                $computedHmac = $hmacProvider.ComputeHash($macInput)
            }
            finally {
                [Array]::Clear($macInput, 0, $macInput.Length)
            }
        }
        finally {
            $hmacProvider.Dispose()
            [Array]::Clear($hmacKey, 0, $hmacKey.Length)
        }

        if (-not (Test-SecureStoreFixedTimeEqual -Left $computedHmac -Right $hmac)) {
            [Array]::Clear($iv, 0, $iv.Length)
            [Array]::Clear($ciphertext, 0, $ciphertext.Length)
            [Array]::Clear($hmac, 0, $hmac.Length)
            [Array]::Clear($computedHmac, 0, $computedHmac.Length)
            throw 'Secret integrity check failed.'
        }

        [Array]::Clear($computedHmac, 0, $computedHmac.Length)

        $aesProvider = [System.Security.Cryptography.Aes]::Create()
        try {
            $aesProvider.KeySize = 256
            $aesProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aesProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aesProvider.Key = $encryptionKey
            $aesProvider.IV = $iv

            $decryptor = $aesProvider.CreateDecryptor()
            try {
                $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
            }
            finally {
                if ($decryptor -is [System.IDisposable]) {
                    $decryptor.Dispose()
                }
            }
        }
        catch {
            throw 'Secret integrity check failed.'
        }
        finally {
            if ($aesProvider -is [System.IDisposable]) {
                $aesProvider.Dispose()
            }
            [Array]::Clear($encryptionKey, 0, $encryptionKey.Length)
        }

        [Array]::Clear($iv, 0, $iv.Length)
        [Array]::Clear($ciphertext, 0, $ciphertext.Length)
        [Array]::Clear($hmac, 0, $hmac.Length)
    }
    else {
        throw "Unsupported cipher algorithm '$cipherAlgorithm'."
    }

    [Array]::Clear($salt, 0, $salt.Length)

    return $plaintext
}

# Import private helper functions
. "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"

# Import public functions
. "$PSScriptRoot\New-SecureStoreSecret.ps1"
. "$PSScriptRoot\Get-SecureStoreSecret.ps1"
. "$PSScriptRoot\Get-SecureStoreList.ps1"
. "$PSScriptRoot\Test-SecureStoreEnvironment.ps1"
. "$PSScriptRoot\New-SecureStoreCertificate.ps1"

# Export public functions
Export-ModuleMember -Function @(
    'New-SecureStoreSecret',
    'Get-SecureStoreSecret',
    'Get-SecureStoreList',
    'Test-SecureStoreEnvironment',
    'New-SecureStoreCertificate'
)

# Module initialization
Write-Verbose "SecureStore v2.0 loaded - Default path: $script:DefaultSecureStorePath"