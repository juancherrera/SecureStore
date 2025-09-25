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
function New-SecureStoreCertificate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [SecureStoreSecureStringTransformation()]
        [System.Security.SecureString]$Password,

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
                    # Export a PEM when requested while ensuring buffers are cleared afterwards.
                    $certBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    try {
                        $pemContent = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($certBytes, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----"
                        $pemBytes = [System.Text.Encoding]::ASCII.GetBytes($pemContent)
                        try {
                            Write-SecureStoreFile -Path $pemPath -Bytes $pemBytes
                        }
                        finally {
                            [Array]::Clear($pemBytes, 0, $pemBytes.Length)
                        }
                    }
                    finally {
                        [Array]::Clear($certBytes, 0, $certBytes.Length)
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
