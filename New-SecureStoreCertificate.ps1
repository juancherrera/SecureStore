<#
.SYNOPSIS
Creates a password-protected self-signed certificate within SecureStore.

.DESCRIPTION
New-SecureStoreCertificate provisions RSA or ECDSA self-signed certificates, exporting a
PFX protected by the supplied password and optionally a PEM. It supports SAN and EKU entries,
ensures atomic writes, and removes transient certificates from the Windows store when finished.

.PARAMETER CertificateName
Logical name used for the output PFX/PEM files.

.PARAMETER Password
Password protecting the exported PFX. Accepts plain text or SecureString.

.PARAMETER FolderPath
Base SecureStore path containing the certs directory. Defaults to the module's standard path.

.PARAMETER ValidityYears
Number of years the certificate remains valid.

.PARAMETER Subject
Optional X.500 subject name. Defaults to CN=<CertificateName> when omitted.

.PARAMETER Algorithm
Certificate key algorithm. Supports RSA or ECDSA.

.PARAMETER KeyLength
RSA key length in bits. Ignored for ECDSA certificates.

.PARAMETER CurveName
ECDSA curve name. Ignored for RSA certificates.

.PARAMETER DnsName
Optional DNS subject alternative names.

.PARAMETER IpAddress
Optional IP subject alternative names.

.PARAMETER Email
Optional email subject alternative names.

.PARAMETER Uri
Optional URI subject alternative names.

.PARAMETER EnhancedKeyUsage
Optional EKU list to embed within the certificate.

.PARAMETER ExportPem
Switch to export a PEM copy alongside the PFX.

.INPUTS
System.String, System.Security.SecureString for the Password parameter.

.OUTPUTS
PSCustomObject with certificate metadata and file paths.

.EXAMPLE
New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -ExportPem

Creates an RSA certificate stored as WebApp.pfx and WebApp.pem.

.EXAMPLE
$secure = Read-Host 'PFX password' -AsSecureString
New-SecureStoreCertificate -CertificateName 'Api' -Password $secure -Algorithm ECDSA -CurveName nistP256 -ValidityYears 2

Creates an ECDSA certificate valid for two years and keeps only a PFX export.

.NOTES
PFX export always requires a password. Temporary files are removed once the move succeeds.

.LINK
Get-SecureStoreList
#>

function ConvertTo-SecureStorePemBlock {
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Label,
        [Parameter(Mandatory = $true)][ValidateNotNull()][byte[]]$Data
    )

    $base64 = [Convert]::ToBase64String($Data, 'InsertLineBreaks')
    return "-----BEGIN $Label-----`n$base64`n-----END $Label-----"
}

function ConvertTo-SecureStoreDerLength {
    param([Parameter(Mandatory = $true)][ValidateRange(0, [int]::MaxValue)] [int]$Length)

    if ($Length -lt 0x80) {
        return ,([byte]$Length)
    }

    $segments = @()
    $remaining = $Length
    while ($remaining -gt 0) {
        $segments = ,([byte]($remaining -band 0xFF)) + $segments
        $remaining = $remaining -shr 8
    }

    $result = New-Object byte[] (1 + $segments.Length)
    $result[0] = [byte](0x80 -bor $segments.Length)
    for ($i = 0; $i -lt $segments.Length; $i++) {
        $result[$i + 1] = $segments[$i]
    }

    return $result
}

function ConvertTo-SecureStoreDerInteger {
    param([Parameter(Mandatory = $true)][ValidateNotNull()][byte[]]$Value)

    $normalized = $Value.Clone()
    $offset = 0
    while (($offset -lt $normalized.Length - 1) -and ($normalized[$offset] -eq 0)) {
        $offset++
    }

    if ($offset -gt 0) {
        $trimmed = New-Object byte[] ($normalized.Length - $offset)
        [Array]::Copy($normalized, $offset, $trimmed, 0, $trimmed.Length)
        $normalized = $trimmed
    }

    if ($normalized.Length -eq 0) {
        $normalized = ,([byte]0)
    }
    elseif (($normalized[0] -band 0x80) -ne 0) {
        $prefixed = New-Object byte[] ($normalized.Length + 1)
        $prefixed[0] = 0
        [Array]::Copy($normalized, 0, $prefixed, 1, $normalized.Length)
        $normalized = $prefixed
    }

    $lengthBytes = ConvertTo-SecureStoreDerLength -Length $normalized.Length
    $result = New-Object byte[] (1 + $lengthBytes.Length + $normalized.Length)
    $result[0] = 0x02
    [Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    [Array]::Copy($normalized, 0, $result, 1 + $lengthBytes.Length, $normalized.Length)

    [Array]::Clear($normalized, 0, $normalized.Length)
    return $result
}

function ConvertTo-SecureStoreDerOctetString {
    param([Parameter(Mandatory = $true)][ValidateNotNull()][byte[]]$Value)

    $lengthBytes = ConvertTo-SecureStoreDerLength -Length $Value.Length
    $result = New-Object byte[] (1 + $lengthBytes.Length + $Value.Length)
    $result[0] = 0x04
    [Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    [Array]::Copy($Value, 0, $result, 1 + $lengthBytes.Length, $Value.Length)
    return $result
}

function ConvertTo-SecureStoreDerBitString {
    param([Parameter(Mandatory = $true)][ValidateNotNull()][byte[]]$Value)

    $lengthBytes = ConvertTo-SecureStoreDerLength -Length ($Value.Length + 1)
    $result = New-Object byte[] (1 + $lengthBytes.Length + $Value.Length + 1)
    $result[0] = 0x03
    [Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    $result[1 + $lengthBytes.Length] = 0x00
    [Array]::Copy($Value, 0, $result, 2 + $lengthBytes.Length, $Value.Length)
    return $result
}

function ConvertTo-SecureStoreDerObjectIdentifier {
    param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OidValue)

    $parts = $OidValue.Split('.')
    if ($parts.Length -lt 2) {
        throw "Invalid OID value '$OidValue'."
    }

    $encoded = New-Object System.Collections.Generic.List[byte]
    $encoded.Add([byte](([int]$parts[0] * 40) + [int]$parts[1])) | Out-Null
    for ($i = 2; $i -lt $parts.Length; $i++) {
        $value = [int]$parts[$i]
        $stack = @()
        do {
            $stack = ,([byte]($value -band 0x7F)) + $stack
            $value = $value -shr 7
        } while ($value -gt 0)

        for ($j = 0; $j -lt $stack.Length; $j++) {
            $byteValue = $stack[$j]
            if ($j -lt $stack.Length - 1) {
                $byteValue = $byteValue -bor 0x80
            }
            $encoded.Add([byte]$byteValue) | Out-Null
        }
    }

    $body = $encoded.ToArray()
    $lengthBytes = ConvertTo-SecureStoreDerLength -Length $body.Length
    $result = New-Object byte[] (1 + $lengthBytes.Length + $body.Length)
    $result[0] = 0x06
    [Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    [Array]::Copy($body, 0, $result, 1 + $lengthBytes.Length, $body.Length)
    return $result
}

function ConvertTo-SecureStoreDerContextSpecific {
    param(
        [Parameter(Mandatory = $true)][ValidateRange(0, 30)][int]$Tag,
        [Parameter(Mandatory = $true)][ValidateNotNull()][byte[]]$Content
    )

    $lengthBytes = ConvertTo-SecureStoreDerLength -Length $Content.Length
    $result = New-Object byte[] (1 + $lengthBytes.Length + $Content.Length)
    $result[0] = [byte](0xA0 + $Tag)
    [Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    [Array]::Copy($Content, 0, $result, 1 + $lengthBytes.Length, $Content.Length)
    return $result
}

function ConvertTo-SecureStoreDerSequence {
    param([Parameter(Mandatory = $true)][ValidateNotNull()][byte[][]]$Elements)

    $filtered = @($Elements | Where-Object { $_ -ne $null })
    $totalLength = 0
    foreach ($element in $filtered) {
        $totalLength += $element.Length
    }

    $lengthBytes = ConvertTo-SecureStoreDerLength -Length $totalLength
    $result = New-Object byte[] (1 + $lengthBytes.Length + $totalLength)
    $result[0] = 0x30
    [Array]::Copy($lengthBytes, 0, $result, 1, $lengthBytes.Length)
    $offset = 1 + $lengthBytes.Length
    foreach ($element in $filtered) {
        [Array]::Copy($element, 0, $result, $offset, $element.Length)
        $offset += $element.Length
    }

    return $result
}

function Export-SecureStoreCertificatePrivateKeyPem {
    param(
        [Parameter(Mandatory = $true)][ValidateNotNull()][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][ValidateSet('RSA', 'ECDSA')][string]$Algorithm,
        [Parameter()][string]$CurveName
    )

    if (-not $Certificate.HasPrivateKey) {
        return $null
    }

    if ($Algorithm -eq 'RSA') {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        if (-not $rsa) { return $null }

        try {
            $parameters = $rsa.ExportParameters($true)
        }
        catch {
            if ($rsa -is [System.IDisposable]) { $rsa.Dispose() }
            throw
        }

        try {
            $zero = New-Object byte[] 1
            $version = ConvertTo-SecureStoreDerInteger -Value $zero
            $modulus = ConvertTo-SecureStoreDerInteger -Value $parameters.Modulus
            $publicExponent = ConvertTo-SecureStoreDerInteger -Value $parameters.Exponent
            $privateExponent = ConvertTo-SecureStoreDerInteger -Value $parameters.D
            $prime1 = ConvertTo-SecureStoreDerInteger -Value $parameters.P
            $prime2 = ConvertTo-SecureStoreDerInteger -Value $parameters.Q
            $exponent1 = ConvertTo-SecureStoreDerInteger -Value $parameters.DP
            $exponent2 = ConvertTo-SecureStoreDerInteger -Value $parameters.DQ
            $coefficient = ConvertTo-SecureStoreDerInteger -Value $parameters.InverseQ

            $sequence = ConvertTo-SecureStoreDerSequence -Elements @(
                $version,
                $modulus,
                $publicExponent,
                $privateExponent,
                $prime1,
                $prime2,
                $exponent1,
                $exponent2,
                $coefficient
            )

            $pem = ConvertTo-SecureStorePemBlock -Label 'RSA PRIVATE KEY' -Data $sequence
            [Array]::Clear($sequence, 0, $sequence.Length)
            return $pem
        }
        finally {
            if ($parameters.D) { [Array]::Clear($parameters.D, 0, $parameters.D.Length) }
            if ($parameters.DP) { [Array]::Clear($parameters.DP, 0, $parameters.DP.Length) }
            if ($parameters.DQ) { [Array]::Clear($parameters.DQ, 0, $parameters.DQ.Length) }
            if ($parameters.Exponent) { [Array]::Clear($parameters.Exponent, 0, $parameters.Exponent.Length) }
            if ($parameters.InverseQ) { [Array]::Clear($parameters.InverseQ, 0, $parameters.InverseQ.Length) }
            if ($parameters.Modulus) { [Array]::Clear($parameters.Modulus, 0, $parameters.Modulus.Length) }
            if ($parameters.P) { [Array]::Clear($parameters.P, 0, $parameters.P.Length) }
            if ($parameters.Q) { [Array]::Clear($parameters.Q, 0, $parameters.Q.Length) }
            if ($rsa -is [System.IDisposable]) { $rsa.Dispose() }
        }
    }

    $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
    if (-not $ecdsa) { return $null }

    try {
        $parameters = $ecdsa.ExportParameters($true)
    }
    catch {
        if ($ecdsa -is [System.IDisposable]) { $ecdsa.Dispose() }
        throw
    }

    try {
        $versionBytes = New-Object byte[] 1
        $versionBytes[0] = 1
        $version = ConvertTo-SecureStoreDerInteger -Value $versionBytes

        $keySize = if ($parameters.D) { $parameters.D.Length } else { 0 }
        if ($parameters.Q.X -and ($parameters.Q.X.Length -gt $keySize)) {
            $keySize = $parameters.Q.X.Length
        }
        if ($parameters.Q.Y -and ($parameters.Q.Y.Length -gt $keySize)) {
            $keySize = $parameters.Q.Y.Length
        }

        $padded = if ($parameters.D) {
            $buffer = New-Object byte[] $keySize
            $offset = $keySize - $parameters.D.Length
            if ($offset -lt 0) { throw 'ECDSA private key length mismatch.' }
            [Array]::Copy($parameters.D, 0, $buffer, $offset, $parameters.D.Length)
            $buffer
        }
        else {
            New-Object byte[] 0
        }

        $privateKey = ConvertTo-SecureStoreDerOctetString -Value $padded
        if ($padded.Length -gt 0) {
            [Array]::Clear($padded, 0, $padded.Length)
        }

        $curveOid = $null
        if (-not [string]::IsNullOrWhiteSpace($CurveName)) {
            switch ($CurveName.ToLowerInvariant()) {
                'nistp256' { $curveOid = '1.2.840.10045.3.1.7' }
                'nistp384' { $curveOid = '1.3.132.0.34' }
                'nistp521' { $curveOid = '1.3.132.0.35' }
            }
        }

        if (-not $curveOid) {
            $length = if ($parameters.Q.X) { $parameters.Q.X.Length } else { 0 }
            switch ($length) {
                32 { $curveOid = '1.2.840.10045.3.1.7' }
                48 { $curveOid = '1.3.132.0.34' }
                66 { $curveOid = '1.3.132.0.35' }
                default { throw 'Unable to determine ECDSA curve OID.' }
            }
        }

        $parametersElement = ConvertTo-SecureStoreDerContextSpecific -Tag 0 -Content (ConvertTo-SecureStoreDerObjectIdentifier -OidValue $curveOid)

        $publicBuffer = if ($parameters.Q.X -and $parameters.Q.Y) {
            $buffer = New-Object byte[] (1 + $parameters.Q.X.Length + $parameters.Q.Y.Length)
            $buffer[0] = 0x04
            [Array]::Copy($parameters.Q.X, 0, $buffer, 1, $parameters.Q.X.Length)
            [Array]::Copy($parameters.Q.Y, 0, $buffer, 1 + $parameters.Q.X.Length, $parameters.Q.Y.Length)
            $buffer
        }
        else {
            New-Object byte[] 1
        }

        $publicKey = ConvertTo-SecureStoreDerContextSpecific -Tag 1 -Content (ConvertTo-SecureStoreDerBitString -Value $publicBuffer)
        if ($publicBuffer.Length -gt 0) {
            [Array]::Clear($publicBuffer, 0, $publicBuffer.Length)
        }

        $sequence = ConvertTo-SecureStoreDerSequence -Elements @(
            $version,
            $privateKey,
            $parametersElement,
            $publicKey
        )

        $pem = ConvertTo-SecureStorePemBlock -Label 'EC PRIVATE KEY' -Data $sequence
        [Array]::Clear($sequence, 0, $sequence.Length)
        return $pem
    }
    finally {
        if ($parameters.D) { [Array]::Clear($parameters.D, 0, $parameters.D.Length) }
        if ($parameters.Q.X) { [Array]::Clear($parameters.Q.X, 0, $parameters.Q.X.Length) }
        if ($parameters.Q.Y) { [Array]::Clear($parameters.Q.Y, 0, $parameters.Q.Y.Length) }
        if ($ecdsa -is [System.IDisposable]) { $ecdsa.Dispose() }
    }
}

function New-SecureStoreCertificate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Password,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$FolderPath = $script:DefaultSecureStorePath,

        [Parameter()]
        [ValidateRange(1, 50)]
        [int]$ValidityYears = 1,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Subject,

        [Parameter()]
        [ValidateSet('RSA', 'ECDSA')]
        [string]$Algorithm = 'RSA',

        [Parameter()]
        [ValidateRange(256, 8192)]
        [int]$KeyLength,

        [Parameter()]
        [ValidateSet('nistP256', 'nistP384', 'nistP521')]
        [string]$CurveName,

        [Parameter()]
        [string[]]$DnsName,

        [Parameter()]
        [string[]]$IpAddress,

        [Parameter()]
        [string[]]$Email,

        [Parameter()]
        [string[]]$Uri,

        [Parameter()]
        [string[]]$EnhancedKeyUsage = @('1.3.6.1.5.5.7.3.1'),

        [Parameter()]
        [switch]$ExportPem
    )

    begin {
        if (-not (Get-Command -Name 'Sync-SecureStoreWorkingDirectory' -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot/Sync-SecureStoreWorkingDirectory.ps1"
        }
    }

    process {
        $securePassword = $null
        $certificate = $null
        try {
            # Convert the supplied password to SecureString to avoid persisting plaintext during export.
            $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
            if ($securePassword.Length -le 0) {
                throw [System.ArgumentException]::new('Certificate password cannot be empty.')
            }

            $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
            $subjectName = if ($Subject) { $Subject } else { "CN=$CertificateName" }
            $pfxPath = Join-Path -Path $paths.CertsPath -ChildPath ("$CertificateName.pfx")
            $pemPath = Join-Path -Path $paths.CertsPath -ChildPath ("$CertificateName.pem")

            if (-not $PSCmdlet.ShouldProcess($pfxPath, "Create certificate '$CertificateName'")) {
                return
            }

            if ($Algorithm -eq 'RSA') {
                if (-not $PSBoundParameters.ContainsKey('KeyLength')) {
                    # Default to 3072-bit RSA which aligns with current security guidance.
                    $KeyLength = 3072
                }
                if ($PSBoundParameters.ContainsKey('CurveName')) {
                    throw [System.ArgumentException]::new('CurveName is only applicable when Algorithm is ECDSA.')
                }
            }
            else {
                if ($PSBoundParameters.ContainsKey('KeyLength')) {
                    throw [System.ArgumentException]::new('KeyLength is only applicable when Algorithm is RSA.')
                }
                if (-not $PSBoundParameters.ContainsKey('CurveName')) {
                    # Default to NIST P-256 which is widely supported.
                    $CurveName = 'nistP256'
                }
            }

            $textExtensions = @()
            $sanComponents = @()
            if ($DnsName) { $sanComponents += ($DnsName | ForEach-Object { "dns=$_" }) }
            if ($IpAddress) { $sanComponents += ($IpAddress | ForEach-Object { "ipaddress=$_" }) }
            if ($Email) { $sanComponents += ($Email | ForEach-Object { "email=$_" }) }
            if ($Uri) { $sanComponents += ($Uri | ForEach-Object { "url=$_" }) }
            if ($sanComponents.Count -gt 0) {
                $textExtensions += "2.5.29.17={text}$($sanComponents -join '&')"
            }
            if ($EnhancedKeyUsage -and $EnhancedKeyUsage.Count -gt 0) {
                $textExtensions += "2.5.29.37={text}$($EnhancedKeyUsage -join ',')"
            }

            $certificateParams = @{
                Subject           = $subjectName
                CertStoreLocation = 'Cert:\CurrentUser\My'
                NotAfter          = (Get-Date).AddYears($ValidityYears)
                KeyExportPolicy   = 'Exportable'
                KeySpec           = 'Signature'
                HashAlgorithm     = 'SHA256'
            }

            if ($Algorithm -eq 'RSA' -and $script:IsWindowsPlatform) {
                # Use the enhanced provider on Windows for stronger key storage support.
                $certificateParams['Provider'] = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            }

            if ($Algorithm -eq 'RSA') {
                $certificateParams['KeyAlgorithm'] = 'RSA'
                $certificateParams['KeyLength'] = $KeyLength
            }
            else {
                $certificateParams['KeyAlgorithm'] = 'ECDSA'
                $certificateParams['CurveExportPolicy'] = 'Exact'
                $certificateParams['CurveName'] = $CurveName
            }

            if ($textExtensions.Count -gt 0) {
                $certificateParams['Type'] = 'Custom'
                $certificateParams['TextExtension'] = $textExtensions
            }

            if (Get-Command -Name 'New-SelfSignedCertificate' -ErrorAction SilentlyContinue) {
                $certificate = New-SelfSignedCertificate @certificateParams
            }
            else {
                $notBefore = [System.DateTimeOffset]::Now
                $notAfter = $notBefore.AddYears($ValidityYears)
                if ($notAfter -lt $notBefore) {
                    $notAfter = $notBefore.AddYears(1)
                }

                if ($Algorithm -eq 'RSA') {
                    $key = [System.Security.Cryptography.RSA]::Create($KeyLength)
                    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($subjectName, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                }
                else {
                    $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName($CurveName)
                    $key = [System.Security.Cryptography.ECDsa]::Create($curve)
                    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($subjectName, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                }

                try {
                    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false))
                    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $false))

                    if ($DnsName -or $IpAddress -or $Email -or $Uri) {
                        $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
                        foreach ($dns in ($DnsName | Where-Object { $_ })) { $sanBuilder.AddDnsName($dns) }
                        foreach ($ip in ($IpAddress | Where-Object { $_ })) { $sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse($ip)) }
                        foreach ($address in ($Email | Where-Object { $_ })) { $sanBuilder.AddEmailAddress($address) }
                        foreach ($link in ($Uri | Where-Object { $_ })) { $sanBuilder.AddUri([System.Uri]$link) }
                        $request.CertificateExtensions.Add($sanBuilder.Build())
                    }

                    if ($EnhancedKeyUsage -and $EnhancedKeyUsage.Count -gt 0) {
                        $ekuCollection = [System.Security.Cryptography.OidCollection]::new()
                        foreach ($eku in $EnhancedKeyUsage) {
                            if (-not [string]::IsNullOrWhiteSpace($eku)) {
                                [void]$ekuCollection.Add([System.Security.Cryptography.Oid]::new($eku))
                            }
                        }
                        if ($ekuCollection.Count -gt 0) {
                            $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuCollection, $false))
                        }
                    }

                    $certificate = $request.CreateSelfSigned($notBefore, $notAfter)
                }
                finally {
                    if ($key -and ($key -is [System.IDisposable])) {
                        $key.Dispose()
                    }
                }
            }

            $tempPfxPath = "$pfxPath.tmp"
            $useTempFile = $true
            if (Test-Path -LiteralPath $tempPfxPath) {
                Remove-Item -LiteralPath $tempPfxPath -Force
            }

            try {
                # Export to a temporary file first to guarantee the final move is atomic and password protected.
                if (Get-Command -Name 'Export-PfxCertificate' -ErrorAction SilentlyContinue) {
                    Export-PfxCertificate -Cert $certificate -FilePath $tempPfxPath -Password $securePassword | Out-Null
                }
                else {
                    $useTempFile = $false
                    # Convert the SecureString to a BSTR only for the duration of the export call.
                    $passwordHandle = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
                    $pfxBytes = $null
                    try {
                        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordHandle)
                        try {
                            $pfxBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $plain)
                        }
                        finally {
                            if ($plain) {
                                $chars = $plain.ToCharArray()
                                [Array]::Clear($chars, 0, $chars.Length)
                            }
                        }
                    }
                    finally {
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordHandle)
                    }

                    if ($pfxBytes) {
                        try {
                            Write-SecureStoreFile -Path $pfxPath -Bytes $pfxBytes
                        }
                        finally {
                            [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
                        }
                    }
                }

                if ($useTempFile) {
                    Move-Item -LiteralPath $tempPfxPath -Destination $pfxPath -Force
                }

                if ($ExportPem.IsPresent) {
                    # Export a PEM containing both the certificate and private key when requested.
                    $pemSections = @()
                    $certBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    try {
                        $pemSections += ConvertTo-SecureStorePemBlock -Label 'CERTIFICATE' -Data $certBytes
                    }
                    finally {
                        [Array]::Clear($certBytes, 0, $certBytes.Length)
                    }

                    try {
                        $privateKeyPem = Export-SecureStoreCertificatePrivateKeyPem -Certificate $certificate -Algorithm $Algorithm -CurveName $CurveName
                        if (-not $privateKeyPem) {
                            throw [System.InvalidOperationException]::new('Private key export returned no data.')
                        }
                        $pemSections += $privateKeyPem
                    }
                    catch {
                        throw [System.InvalidOperationException]::new("Failed to export PEM private key for certificate '$CertificateName'.", $_.Exception)
                    }

                    $lineBreak = [System.Environment]::NewLine
                    $pemContent = [string]::Join("$lineBreak$lineBreak", $pemSections)
                    $pemBytes = [System.Text.Encoding]::ASCII.GetBytes($pemContent + $lineBreak)
                    try {
                        Write-SecureStoreFile -Path $pemPath -Bytes $pemBytes
                    }
                    finally {
                        [Array]::Clear($pemBytes, 0, $pemBytes.Length)
                    }
                }
            }
            finally {
                if ($useTempFile -and (Test-Path -LiteralPath $tempPfxPath)) {
                    Remove-Item -LiteralPath $tempPfxPath -Force
                }
            }

            $thumbprint = $certificate.Thumbprint
            $notAfter = $certificate.NotAfter

            try {
                # Remove the temporary cert from the personal store to avoid cluttering the user profile.
                Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose "Failed to remove certificate '$thumbprint' from store: $($_.Exception.Message)"
            }

            [PSCustomObject]@{
                CertificateName = $CertificateName
                Subject         = $subjectName
                Algorithm       = $Algorithm
                KeyLength       = if ($Algorithm -eq 'RSA') { $KeyLength } else { $null }
                CurveName       = if ($Algorithm -eq 'ECDSA') { $CurveName } else { $null }
                Thumbprint      = $thumbprint
                NotAfter        = $notAfter
                Paths           = [PSCustomObject]@{
                    Pfx = $pfxPath
                    Pem = if ($ExportPem) { $pemPath } else { $null }
                }
            }
        }
        catch {
            throw [System.InvalidOperationException]::new("Failed to create certificate '$CertificateName'.", $_.Exception)
        }
        finally {
            if ($securePassword) {
                $securePassword.Dispose()
            }
            if ($certificate -and ($certificate -is [System.IDisposable])) {
                $certificate.Dispose()
            }
        }
    }
}
