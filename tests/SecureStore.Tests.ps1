Import-Module "$PSScriptRoot/../SecureStore.psd1" -Force

Describe 'SecureStore defaults' {
    It 'uses C:\\SecureStore on Windows platforms' {
        InModuleScope SecureStore {
            $originalFlag = $script:IsWindowsPlatform
            try {
                $script:IsWindowsPlatform = $true
                Get-SecureStoreDefaultPath | Should -Be 'C:\\SecureStore'
            }
            finally {
                $script:IsWindowsPlatform = $originalFlag
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
    It 'converts plain text values into SecureString instances' {
        InModuleScope SecureStore {
            $secure = ConvertTo-SecureStoreSecureString -InputObject 'topsecret'
            $secure | Should -BeOfType ([System.Security.SecureString])

            $bytes = Get-SecureStorePlaintextData -SecureString $secure
            [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Be 'topsecret'
        }
    }

    It 'converts arrays of plain text to secure strings' {
        InModuleScope SecureStore {
            $result = ConvertTo-SecureStoreSecureString -InputObject @('first', 'second')

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
            $result.SecretPath | Should -Match 'secrets$'
            $result.LegacySecretPath | Should -Match 'secret$'
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
            $result.LegacySecretPath | Should -Match 'secret$'
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
            $result.LegacySecretPath | Should -Be (Join-Path -Path $result.BasePath -ChildPath 'secret')
        }
    }
}

Describe 'New-SecureStoreSecret' {
    BeforeEach {
        InModuleScope SecureStore {
            $script:MockFiles = @{}
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath   = '/securestore'
                    BinPath    = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    LegacySecretPath = '/securestore/secret'
                    CertsPath  = '/securestore/certs'
                }
            }
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param([string]$Path, [string]$LiteralPath)
                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } elseif ($PSBoundParameters.ContainsKey('Path')) { $Path } else { $null }
                switch ($target) {
                    '/securestore/bin/Database.bin' { return $false }
                    '/securestore/bin/Api.bin'     { return $true }
                    default { return $true }
                }
            }
            Mock -CommandName Write-SecureStoreFile -ModuleName SecureStore -MockWith {
                param([string]$Path, [byte[]]$Bytes)
                $script:MockFiles[$Path] = $Bytes.Clone()
            }
            Mock -CommandName Read-SecureStoreByteArray -ModuleName SecureStore -MockWith {
                param([string]$Path)
                [void]$Path
                return [byte[]](1..32)
            }
        }
    }

    It 'creates or updates a secret using the documented example' {
        InModuleScope SecureStore {
            New-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' -Password 'P@ssw0rd!'
            $script:MockFiles.Keys | Should -Contain '/securestore/bin/Database.bin'
            $script:MockFiles.Keys | Should -Contain '/securestore/secrets/prod.secret'
            $secretBytes = $script:MockFiles['/securestore/secrets/prod.secret']
            [System.Text.Encoding]::UTF8.GetString($secretBytes) | Should -Not -BeNullOrEmpty
        }
    }

    It 'accepts secure string input as per help example' {
        InModuleScope SecureStore {
            $secure = [System.Security.SecureString]::new()
            foreach ($ch in 'token-value'.ToCharArray()) { $secure.AppendChar($ch) }
            $secure.MakeReadOnly()
            New-SecureStoreSecret -KeyName 'Api' -SecretFileName 'token.secret' -Password $secure -Confirm:$false
            $script:MockFiles.Keys | Should -Contain '/securestore/secrets/token.secret'
        }
    }

    It 'redirects legacy secret paths into the preferred secrets directory' {
        InModuleScope SecureStore {
            New-SecureStoreSecret -KeyName 'Legacy' -SecretFileName '/securestore/secret/legacy.secret' -Password 'value'
            $script:MockFiles.Keys | Should -Contain '/securestore/secrets/legacy.secret'
            $script:MockFiles.Keys | Should -Not -Contain '/securestore/secret/legacy.secret'
        }
    }

    It 'respects -WhatIf and avoids file writes' {
        InModuleScope SecureStore {
            New-SecureStoreSecret -KeyName 'test' -SecretFileName 'secret.json' -Password 'value' -WhatIf
            Assert-MockCalled -CommandName Write-SecureStoreFile -ModuleName SecureStore -Times 0
        }
    }
}

Describe 'Get-SecureStoreSecret' {
    BeforeAll {
        InModuleScope SecureStore {
            $script:SampleKey = New-Object byte[] 32
            for ($i = 0; $i -lt $script:SampleKey.Length; $i++) { $script:SampleKey[$i] = [byte]$i }
            $plaintext = [System.Text.Encoding]::UTF8.GetBytes('P@ssw0rd!')
            $script:SamplePayload = Protect-SecureStoreSecret -Plaintext $plaintext -MasterKey $script:SampleKey
        }
    }

    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath   = '/securestore'
                    BinPath    = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    LegacySecretPath = '/securestore/secret'
                    CertsPath  = '/securestore/certs'
                }
            }
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param([string]$Path, [string]$LiteralPath)
                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } elseif ($PSBoundParameters.ContainsKey('Path')) { $Path } else { $null }
                switch ($target) {
                    '/securestore/bin/Database.bin' { return $true }
                    '/securestore/secrets/prod.secret' { return $true }
                    './bin/Api.bin' { return $true }
                    './secrets/api.secret' { return $true }
                    default { return $true }
                }
            }
            Mock -CommandName Read-SecureStoreByteArray -ModuleName SecureStore -MockWith {
                return $script:SampleKey.Clone()
            }
            Mock -CommandName Read-SecureStoreText -ModuleName SecureStore -MockWith {
                return $script:SamplePayload
            }
        }
    }

    It 'returns plain text as shown in the help example' {
        InModuleScope SecureStore {
            Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' | Should -Be 'P@ssw0rd!'
        }
    }

    It 'returns PSCredential using explicit paths as per help example' {
        InModuleScope SecureStore {
            $credential = Get-SecureStoreSecret -KeyPath './bin/Api.bin' -SecretPath './secrets/api.secret' -AsCredential -UserName 'api-user'
            $credential.UserName | Should -Be 'api-user'
            $credential.GetNetworkCredential().Password | Should -Be 'P@ssw0rd!'
        }
    }

    It 'falls back to the legacy secret folder when the preferred path is empty' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secrets/prod.secret' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secret/prod.secret' } -MockWith { return $true }
            Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' | Should -Be 'P@ssw0rd!'
        }
    }

    It 'supports path-like KeyName and SecretFileName inputs' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secrets/prod.secret' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secret/prod.secret' } -MockWith { return $true }
            Get-SecureStoreSecret -KeyName '/securestore/bin/Database.bin' -SecretFileName '/securestore/secret/prod.secret' | Should -Be 'P@ssw0rd!'
        }
    }

    It 'throws a friendly error when the key file is missing' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/bin/Database.bin' } -MockWith { return $false }
            { Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' } | Should -Throw -ErrorId * -ExceptionType ([System.InvalidOperationException])
        }
    }
}

Describe 'New-SecureStoreCertificate' {
    BeforeEach {
        InModuleScope SecureStore {
            $script:MockFiles = @{}
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath   = '/securestore'
                    BinPath    = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    LegacySecretPath = '/securestore/secret'
                    CertsPath  = '/securestore/certs'
                }
            }
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith {
                param([string]$Path, [string]$LiteralPath)
                $target = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } elseif ($PSBoundParameters.ContainsKey('Path')) { $Path } else { $null }
                if ($target -like '*.tmp') { return $false }
                return $true
            }
            Mock -CommandName Write-SecureStoreFile -ModuleName SecureStore -MockWith {
                param([string]$Path, [byte[]]$Bytes)
                $script:MockFiles[$Path] = $Bytes.Clone()
            }
            Mock -CommandName Move-Item -ModuleName SecureStore -MockWith {
                param(
                    [Parameter(Mandatory = $true)][string]$LiteralPath,
                    [Parameter(Mandatory = $true)][string]$Destination
                )

                if ($script:MockFiles.ContainsKey($LiteralPath)) {
                    $script:MockFiles[$Destination] = $script:MockFiles[$LiteralPath]
                    $script:MockFiles.Remove($LiteralPath)
                }
            }
            Mock -CommandName Remove-Item -ModuleName SecureStore

        }
    }

    It 'creates a certificate and exports PEM as documented' {
        InModuleScope SecureStore {
            $result = New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -ExportPem -Confirm:$false
            $result.CertificateName | Should -Be 'WebApp'
            $script:MockFiles.Keys | Should -Contain '/securestore/certs/WebApp.pfx'
            $script:MockFiles.Keys | Should -Contain '/securestore/certs/WebApp.pem'
            $pemContent = [System.Text.Encoding]::ASCII.GetString($script:MockFiles['/securestore/certs/WebApp.pem'])
            $pemContent | Should -Match 'BEGIN CERTIFICATE'
            $pemContent | Should -Match 'BEGIN RSA PRIVATE KEY'
        }
    }

    It 'supports the ECDSA help example' {
        InModuleScope SecureStore {
            $secure = [System.Security.SecureString]::new()
            foreach ($ch in 'Sup3rPfx!'.ToCharArray()) { $secure.AppendChar($ch) }
            $secure.MakeReadOnly()
            New-SecureStoreCertificate -CertificateName 'Api' -Password $secure -Algorithm ECDSA -CurveName nistP256 -ValidityYears 2 -Confirm:$false
            $script:MockFiles.Keys | Should -Contain '/securestore/certs/Api.pfx'
        }
    }

    It 'exports PEM including EC private key for ECDSA certificates' {
        InModuleScope SecureStore {
            $result = New-SecureStoreCertificate -CertificateName 'Ecc' -Password 'Sup3rPfx!' -Algorithm ECDSA -CurveName nistP256 -ExportPem -Confirm:$false
            $result.Paths.Pem | Should -Be '/securestore/certs/Ecc.pem'
            $pemContent = [System.Text.Encoding]::ASCII.GetString($script:MockFiles['/securestore/certs/Ecc.pem'])
            $pemContent | Should -Match 'BEGIN CERTIFICATE'
            $pemContent | Should -Match 'BEGIN EC PRIVATE KEY'
        }
    }

    It 'honours -WhatIf to avoid export' {
        InModuleScope SecureStore {
            New-SecureStoreCertificate -CertificateName 'Skip' -Password 'pass123!' -WhatIf
            $script:MockFiles.Keys | Should -Not -Contain '/securestore/certs/Skip.pfx'
        }
    }
}

Describe 'Get-SecureStoreList' {
    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath   = '/securestore'
                    BinPath    = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    LegacySecretPath = '/securestore/secret'
                    CertsPath  = '/securestore/certs'
                }
            }
            Mock -CommandName Get-ChildItem -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/bin' } -MockWith {
                return @([pscustomobject]@{ Name = 'Database.bin'; FullName = '/securestore/bin/Database.bin' })
            }
            Mock -CommandName Get-ChildItem -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secrets' } -MockWith {
                return @([pscustomobject]@{ Name = 'prod.secret'; FullName = '/securestore/secrets/prod.secret' })
            }
            Mock -CommandName Get-ChildItem -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/certs' } -MockWith {
                return @([pscustomobject]@{ Name = 'WebApp.cer'; FullName = '/securestore/certs/WebApp.cer'; Extension = '.cer' })
            }
            Mock -CommandName New-Object -ModuleName SecureStore -ParameterFilter { $TypeName -eq 'System.Security.Cryptography.X509Certificates.X509Certificate2' } -MockWith {
                $certObject = [pscustomobject]@{
                    Thumbprint = 'THUMB123'
                    NotAfter   = (Get-Date).AddDays(10)
                }
                $certObject | Add-Member -MemberType ScriptMethod -Name Dispose -Value { } -Force | Out-Null
                return $certObject
            }
            Mock -CommandName Write-Warning -ModuleName SecureStore
        }
    }

    It 'lists inventory and warns about expiring certificates' {
        InModuleScope SecureStore {
            $result = Get-SecureStoreList -ExpiryWarningDays 45
            $result.Keys | Should -Contain 'Database.bin'
            $result.Secrets | Should -Contain 'prod.secret'
            $result.Certificates | Should -HaveCount 1
            $result.Certificates[0].ExpiresSoon | Should -BeTrue
            Assert-MockCalled -CommandName Write-Warning -ModuleName SecureStore -Times 1
        }
    }

    It 'includes secrets from the legacy folder without duplication' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secret' } -MockWith { return $true }
            Mock -CommandName Get-ChildItem -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secret' } -MockWith {
                return @([pscustomobject]@{ Name = 'legacy.secret'; FullName = '/securestore/secret/legacy.secret' })
            }

            $result = Get-SecureStoreList
            $result.Secrets | Should -Contain 'prod.secret'
            $result.Secrets | Should -Contain 'legacy.secret'
        }
    }
}

Describe 'Test-SecureStoreEnvironment' {
    BeforeEach {
        InModuleScope SecureStore {
            Mock -CommandName Sync-SecureStoreWorkingDirectory -ModuleName SecureStore -MockWith {
                return [PSCustomObject]@{
                    BasePath   = '/securestore'
                    BinPath    = '/securestore/bin'
                    SecretPath = '/securestore/secrets'
                    LegacySecretPath = '/securestore/secret'
                    CertsPath  = '/securestore/certs'
                }
            }
        }
    }

    It 'reports ready when folders exist as per help example' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith { return $true }
            $status = Test-SecureStoreEnvironment
            $status.Ready | Should -BeTrue
            $status.Locations.InSync | Should -BeTrue
        }
    }

    It 'detects missing folders' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secrets' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -eq '/securestore/secret' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -ne '/securestore/secrets' } -MockWith { return $true }
            $status = Test-SecureStoreEnvironment -FolderPath '/securestore'
            $status.Ready | Should -BeFalse
            $status.Paths.SecretExists | Should -BeFalse
        }
    }
}
