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

            $certificate = New-SelfSignedCertificate @certificateParams

            $tempPfxPath = "$pfxPath.tmp"
            if (Test-Path -LiteralPath $tempPfxPath) {
                Remove-Item -LiteralPath $tempPfxPath -Force
            }

            try {
                Export-PfxCertificate -Cert $certificate -FilePath $tempPfxPath -Password $securePassword | Out-Null
                Move-Item -LiteralPath $tempPfxPath -Destination $pfxPath -Force

                if ($ExportPem.IsPresent) {
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
                if (Test-Path -LiteralPath $tempPfxPath) {
                    Remove-Item -LiteralPath $tempPfxPath -Force
                }
            }

            $thumbprint = $certificate.Thumbprint
            $notAfter = $certificate.NotAfter

            try {
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
            throw [System.Exception]::new("Failed to create certificate '$CertificateName'.", $_.Exception)
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
