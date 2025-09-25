Import-Module "$PSScriptRoot/../SecureStore.psd1" -Force

Describe 'SecureStore defaults' {
    It 'uses ProgramData on Windows platforms' {
        InModuleScope SecureStore {
            $originalFlag = $script:IsWindowsPlatform
            $originalProgramData = $env:ProgramData
            try {
                $script:IsWindowsPlatform = $true
                $env:ProgramData = 'C:\\ProgramData'
                $expected = [System.IO.Path]::Combine('C:\\ProgramData', 'SecureStore')
                Get-SecureStoreDefaultPath | Should -Be $expected
            }
            finally {
                $script:IsWindowsPlatform = $originalFlag
                $env:ProgramData = $originalProgramData
            }
        }
    }

    It 'uses the home directory on non-Windows platforms' {
        InModuleScope SecureStore {
            $originalFlag = $script:IsWindowsPlatform
            $originalHome = $env:HOME
            try {
                $script:IsWindowsPlatform = $false
                $env:HOME = '/home/tester'
                [System.Environment]::SetEnvironmentVariable('HOME', '/home/tester')
                Get-SecureStoreDefaultPath | Should -Be (Join-Path -Path $env:HOME -ChildPath '.securestore')
            }
            finally {
                $script:IsWindowsPlatform = $originalFlag
                $env:HOME = $originalHome
                [System.Environment]::SetEnvironmentVariable('HOME', $originalHome)
            }
        }
    }
}

Describe 'SecureStore secure string helpers' {
    It 'transforms plain text values using the argument transformation attribute' {
        InModuleScope SecureStore {
            $attribute = [SecureStoreSecureStringTransformationAttribute]::new()
            $secure = $attribute.Transform($ExecutionContext, 'topsecret')
            $secure | Should -BeOfType ([System.Security.SecureString])

            $bytes = Get-SecureStorePlaintextData -SecureString $secure
            [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Be 'topsecret'
        }
    }

    It 'converts arrays of plain text to secure strings' {
        InModuleScope SecureStore {
            $attribute = [SecureStoreSecureStringTransformationAttribute]::new()
            $result = $attribute.Transform($ExecutionContext, @('first', 'second'))

            $result | Should -HaveCount 2
            foreach ($entry in $result) {
                $entry | Should -BeOfType ([System.Security.SecureString])
            }
        }
    }
}

Describe 'Sync-SecureStoreWorkingDirectory' {
    It 'accepts legacy secret folder but warns about deprecation' {
        InModuleScope SecureStore {
            $script:LegacySecretWarningIssued = $false
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                switch -Wildcard ($target) {
                    '*secrets' { return $false }
                    '*secret' { return $true }
                    default { return $true }
                }
            }
            Mock -CommandName New-Item -ModuleName SecureStore
            Mock -CommandName Write-Warning

            $result = Sync-SecureStoreWorkingDirectory -BasePath '/var/lib/securestore'
            $result.SecretPath | Should -Match 'secrets?$'
            Assert-MockCalled -CommandName Write-Warning -Times 1
        }
    }

    It 'creates the preferred secrets folder when none exists' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $false
            }
            Mock -CommandName New-Item -ModuleName SecureStore

            $result = Sync-SecureStoreWorkingDirectory -BasePath '/opt/securestore'
            $result.SecretPath | Should -Match 'secrets$'
        }
    }

    It 'treats -FolderPath values pointing to the secrets directory as the store root' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $false
            }
            Mock -CommandName New-Item -ModuleName SecureStore

            $inputPath = '/srv/app/secrets'
            $expectedBase = Split-Path -Path ([System.IO.Path]::GetFullPath($inputPath)) -Parent

            $result = Sync-SecureStoreWorkingDirectory -BasePath $inputPath
            $result.SecretPath | Should -Be (Join-Path -Path $result.BasePath -ChildPath 'secrets')
            $result.BasePath | Should -Be $expectedBase
        }
    }
}

Describe 'New-SecureStoreSecret' {
    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath  = '/securestore'
                    BinPath   = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    CertsPath = '/securestore/certs'
                }
            }
        }
    }

    It 'respects -WhatIf and avoids file writes' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $false
            }
            Mock -CommandName Write-SecureStoreFile -ModuleName SecureStore

            New-SecureStoreSecret -KeyName 'test' -SecretFileName 'secret.json' -Password 'value' -WhatIf

            Assert-MockCalled -CommandName Write-SecureStoreFile -ModuleName SecureStore -Times 0
        }
    }

    It 'stores encrypted secret data using authenticated encryption' {
        InModuleScope SecureStore {
            $writes = @{}
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $false
            }
            Mock -CommandName Write-SecureStoreFile -ModuleName SecureStore -MockWith {
                param($Path, $Bytes)
                $writes[$Path] = [byte[]]$Bytes.Clone()
            }

            New-SecureStoreSecret -KeyName 'encKey' -SecretFileName 'secret.txt' -Password 'superSecret!' -Confirm:$false

            $keyPath = '/securestore/bin/encKey.bin'
            $secretPath = '/securestore/secrets/secret.txt'
            $writes.ContainsKey($keyPath) | Should -BeTrue
            $writes.ContainsKey($secretPath) | Should -BeTrue

            $payload = [System.Text.Encoding]::UTF8.GetString($writes[$secretPath])
            $payloadObject = $payload | ConvertFrom-Json
            if ($script:SupportsAesGcm) {
                $payloadObject.Cipher.Algorithm | Should -Be 'AES-GCM'
            }
            else {
                $payloadObject.Cipher.Algorithm | Should -Be 'AES-CBC-HMACSHA256'
            }

            $plaintext = Unprotect-SecureStoreSecret -Payload $payload -MasterKey $writes[$keyPath]
            [System.Text.Encoding]::UTF8.GetString($plaintext) | Should -Be 'superSecret!'
        }
    }

    It 'falls back to AES-CBC with HMAC when AES-GCM is unavailable' {
        InModuleScope SecureStore {
            $writes = @{}
            $originalSupport = $script:SupportsAesGcm
            try {
                $script:SupportsAesGcm = $false

                Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                    param(
                        [string]$Path,
                        [string]$LiteralPath
                    )

                    $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                        $LiteralPath
                    }
                    elseif ($PSBoundParameters.ContainsKey('Path')) {
                        $Path
                    }
                    else {
                        $null
                    }

                    [void]$target
                    return $false
                }

                Mock -CommandName Write-SecureStoreFile -ModuleName SecureStore -MockWith {
                    param($Path, $Bytes)
                    $writes[$Path] = [byte[]]$Bytes.Clone()
                }

                New-SecureStoreSecret -KeyName 'legacyKey' -SecretFileName 'secret.txt' -Password 'compatSecret!' -Confirm:$false

                $secretPath = '/securestore/secrets/secret.txt'
                $payload = [System.Text.Encoding]::UTF8.GetString($writes[$secretPath])
                ($payload | ConvertFrom-Json).Cipher.Algorithm | Should -Be 'AES-CBC-HMACSHA256'

                $plaintext = Unprotect-SecureStoreSecret -Payload $payload -MasterKey $writes['/securestore/bin/legacyKey.bin']
                [System.Text.Encoding]::UTF8.GetString($plaintext) | Should -Be 'compatSecret!'
            }
            finally {
                $script:SupportsAesGcm = $originalSupport
            }
        }
    }
}

Describe 'Get-SecureStoreSecret' {
    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath  = '/securestore'
                    BinPath   = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    CertsPath = '/securestore/certs'
                }
            }
        }
    }

    It 'returns a PSCredential when requested' {
        InModuleScope SecureStore {
            $keyBytes = [byte[]](1..32)
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes('credSecret')
            $payload = Protect-SecureStoreSecret -Plaintext $plaintext -MasterKey $keyBytes
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $true
            }
            $originalReadBytes = Get-Command -Name Read-SecureStoreByteArray -CommandType Function
            $originalReadText = Get-Command -Name Read-SecureStoreText -CommandType Function

            $credential = $null

            try {
                Set-Item -Path function:Read-SecureStoreByteArray -Value ({
                    param([string]$Path)
                    [void]$Path
                    return [byte[]]$keyBytes.Clone()
                }).GetNewClosure()

                Set-Item -Path function:Read-SecureStoreText -Value ({
                    param([string]$Path, [System.Text.Encoding]$Encoding)
                    [void]$Path
                    [void]$Encoding
                    return $payload
                }).GetNewClosure()

                $credential = Get-SecureStoreSecret -KeyName 'credKey' -SecretFileName 'secret.txt' -AsCredential -UserName 'alice'
            }
            finally {
                if ($null -ne $originalReadBytes) {
                    Set-Item -Path function:Read-SecureStoreByteArray -Value $originalReadBytes.ScriptBlock
                }

                if ($null -ne $originalReadText) {
                    Set-Item -Path function:Read-SecureStoreText -Value $originalReadText.ScriptBlock
                }
            }

            $credential.UserName | Should -Be 'alice'
            $credential.GetNetworkCredential().Password | Should -Be 'credSecret'
        }
    }

    It 'throws a sanitized error when the secret file is missing' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                if ($target -like '*bin/credKey.bin') { return $true }
                return $false
            }
            Mock -CommandName Read-SecureStoreByteArray -ModuleName SecureStore -MockWith { param($Path) [void]$Path; return [byte[]]@(0) }

            Should -Throw -ActualValue { Get-SecureStoreSecret -KeyName 'credKey' -SecretFileName 'missing.txt' } -ErrorId * -ExpectedMessage 'Failed to retrieve the requested secret.'
        }
    }
}

Describe 'New-SecureStoreCertificate' {
    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath  = '/securestore'
                    BinPath   = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    CertsPath = '/securestore/certs'
                }
            }
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $false
            }
            Mock -CommandName Remove-Item -ModuleName SecureStore
        }
    }

    It 'rejects invalid key length for ECDSA' {
        InModuleScope SecureStore {
            { New-SecureStoreCertificate -CertificateName 'invalid' -Password 'pass123!' -Algorithm ECDSA -KeyLength 4096 -Confirm:$false } | Should -Throw
        }
    }

    It 'honors -WhatIf and avoids generating certificates' {
        InModuleScope SecureStore {
            function New-SelfSignedCertificate {
                [CmdletBinding(SupportsShouldProcess = $true)]
                param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)
                [void]$Arguments
                if (-not $PSCmdlet.ShouldProcess('Test certificate stub', 'Generate')) {
                    return
                }
            }
            Mock -CommandName New-SelfSignedCertificate -ModuleName SecureStore -MockWith { throw 'Should not be called' }

            New-SecureStoreCertificate -CertificateName 'whatif' -Password 'pass123!' -WhatIf
        }
    }

    It 'exports certificate metadata and paths' {
        InModuleScope SecureStore {
            function New-SelfSignedCertificate {
                [CmdletBinding(SupportsShouldProcess = $true)]
                param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)
                [void]$Arguments
                if (-not $PSCmdlet.ShouldProcess('Test certificate stub', 'Generate')) {
                    return
                }
            }
            function Export-PfxCertificate {
                [CmdletBinding(SupportsShouldProcess = $true)]
                param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)
                [void]$Arguments
                if (-not $PSCmdlet.ShouldProcess('Test certificate stub', 'Export')) {
                    return
                }
            }
            $certObject = New-Object PSObject -Property @{ Thumbprint = 'ABC123'; NotAfter = (Get-Date).AddYears(1) }
            $certObject | Add-Member -MemberType ScriptMethod -Name Export -Value { param($type) [void]$type; return [byte[]](1,2,3) }
            $certObject | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
            Mock -CommandName New-SelfSignedCertificate -ModuleName SecureStore -MockWith { return $certObject }
            Mock -CommandName Export-PfxCertificate -ModuleName SecureStore
            Mock -CommandName Move-Item -ModuleName SecureStore
            Mock -CommandName Write-SecureStoreFile -ModuleName SecureStore

            $result = New-SecureStoreCertificate -CertificateName 'app' -Password 'pass123!' -ExportPem -Confirm:$false
            $result.CertificateName | Should -Be 'app'
            $result.Paths.Pfx | Should -Match 'app.pfx$'
            $result.Paths.Pem | Should -Match 'app.pem$'
            $result.NotAfter | Should -BeGreaterThan (Get-Date)
        }
    }
}

Describe 'Get-SecureStoreList' {
    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath  = '/securestore'
                    BinPath   = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    CertsPath = '/securestore/certs'
                }
            }
        }
    }

    It 'warns when certificates are nearing expiry' {
        InModuleScope SecureStore {
            Mock -CommandName Get-ChildItem -ModuleName SecureStore -MockWith {
                param($LiteralPath, $Filter, $File)
                [void]$Filter
                [void]$File
                switch ($LiteralPath) {
                    '/securestore/bin' { return @([PSCustomObject]@{ Name = 'key.bin'; FullName = '/securestore/bin/key.bin' }) }
                    '/securestore/secrets' { return @([PSCustomObject]@{ Name = 'secret.txt'; FullName = '/securestore/secrets/secret.txt' }) }
                    '/securestore/certs' { return @([PSCustomObject]@{ Name = 'cert.cer'; FullName = '/securestore/certs/cert.cer'; Extension = '.cer' }) }
                }
            }

            $fakeCert = New-Object PSObject -Property @{ Thumbprint = 'XYZ'; NotAfter = (Get-Date).AddDays(5) }
            $fakeCert | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
            Mock -CommandName New-Object -ModuleName SecureStore -ParameterFilter { $TypeName -eq 'System.Security.Cryptography.X509Certificates.X509Certificate2' } -MockWith { $fakeCert }
            Mock -CommandName Write-Warning -ModuleName SecureStore

            $result = Get-SecureStoreList
            $result.Certificates | Should -HaveCount 1
            $result.Certificates[0].ExpiresSoon | Should -BeTrue
            Assert-MockCalled -CommandName Write-Warning -ModuleName SecureStore -Times 1
        }
    }
}

Describe 'Test-SecureStoreEnvironment' {
    It 'reports readiness based on directory existence' {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath  = '/securestore'
                    BinPath   = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    CertsPath = '/securestore/certs'
                }
            }
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param(
                    [string]$Path,
                    [string]$LiteralPath
                )

                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $LiteralPath
                }
                elseif ($PSBoundParameters.ContainsKey('Path')) {
                    $Path
                }
                else {
                    $null
                }

                [void]$target
                return $true
            }

            $status = Test-SecureStoreEnvironment
            $status.Ready | Should -BeTrue
            $status.Paths.SecretExists | Should -BeTrue
        }
    }
}
