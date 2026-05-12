Import-Module "$PSScriptRoot/../SecureStore.psd1" -Force

Describe 'Module packaging' {
    It 'has a valid manifest for PowerShell Gallery packaging' {
        $manifest = Test-ModuleManifest -Path "$PSScriptRoot/../SecureStore.psd1" -ErrorAction Stop
        $manifest.Guid | Should Not Be ([guid]'12345678-1234-1234-1234-123456789012')
        ($manifest.ExportedFunctions.Keys -contains 'New-SecureStoreCredential') | Should Be $true
        ($manifest.ExportedFunctions.Keys -contains 'Get-SecureStoreCredential') | Should Be $true
        ($manifest.ExportedFunctions.Keys -contains 'Set-SecureStoreCredential') | Should Be $true
        ($manifest.ExportedFunctions.Keys -contains 'Get-SecureStoreCredentialList') | Should Be $true
        ($manifest.ExportedFunctions.Keys -contains 'Remove-SecureStoreCredential') | Should Be $true
    }
}

Describe 'SecureStore defaults' {
    It 'uses C:\\SecureStore on Windows platforms' {
        InModuleScope SecureStore {
            $originalFlag = $script:IsWindowsPlatform
            try {
                $script:IsWindowsPlatform = $true
                Get-SecureStoreDefaultPath | Should Be 'C:\\SecureStore'
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
                Get-SecureStoreDefaultPath | Should Be (Join-Path -Path $env:HOME -ChildPath '.securestore')
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
            $secure | Should BeOfType ([System.Security.SecureString])

            $bytes = Get-SecureStorePlaintextData -SecureString $secure
            [System.Text.Encoding]::UTF8.GetString($bytes) | Should Be 'topsecret'
        }
    }

    It 'converts arrays of plain text to secure strings' {
        InModuleScope SecureStore {
            $result = ConvertTo-SecureStoreSecureString -InputObject @('first', 'second')

            @($result).Count | Should Be 2
            foreach ($entry in $result) {
                $entry | Should BeOfType ([System.Security.SecureString])
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
            $result.SecretPath | Should Match 'secrets$'
            $result.LegacySecretPath | Should Match 'secret$'
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
            $result.SecretPath | Should Match 'secrets$'
            $result.LegacySecretPath | Should Match 'secret$'
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
            $result.SecretPath | Should Be (Join-Path -Path $result.BasePath -ChildPath 'secrets')
            $result.BasePath | Should Be $expectedBase
            $result.LegacySecretPath | Should Be (Join-Path -Path $result.BasePath -ChildPath 'secret')
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
                switch -Wildcard ($target) {
                    '*securestore*bin*Database.bin' { return $false }
                    '*securestore*bin*Api.bin'     { return $true }
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
            @($script:MockFiles.Keys | Where-Object { $_ -like '*securestore*bin*Database.bin' }).Count | Should Be 1
            @($script:MockFiles.Keys | Where-Object { $_ -like '*securestore*secrets*prod.secret' }).Count | Should Be 1
            $secretPath = @($script:MockFiles.Keys | Where-Object { $_ -like '*securestore*secrets*prod.secret' })[0]
            $secretBytes = $script:MockFiles[$secretPath]
            [System.Text.Encoding]::UTF8.GetString($secretBytes) | Should Not BeNullOrEmpty
        }
    }

    It 'accepts secure string input as per help example' {
        InModuleScope SecureStore {
            $secure = [System.Security.SecureString]::new()
            foreach ($ch in 'token-value'.ToCharArray()) { $secure.AppendChar($ch) }
            $secure.MakeReadOnly()
            New-SecureStoreSecret -KeyName 'Api' -SecretFileName 'token.secret' -Password $secure -Confirm:$false
            @($script:MockFiles.Keys | Where-Object { $_ -like '*securestore*secrets*token.secret' }).Count | Should Be 1
        }
    }

    It 'redirects legacy secret paths into the preferred secrets directory' {
        InModuleScope SecureStore {
            New-SecureStoreSecret -KeyName 'Legacy' -SecretFileName '/securestore/secret/legacy.secret' -Password 'value'
            @($script:MockFiles.Keys | Where-Object { $_ -like '*securestore*secrets*legacy.secret' }).Count | Should Be 1
            @($script:MockFiles.Keys | Where-Object { $_ -like '*securestore*secret*legacy.secret' -and $_ -notlike '*securestore*secrets*legacy.secret' }).Count | Should Be 0
        }
    }

    It 'respects -WhatIf and avoids file writes' {
        InModuleScope SecureStore {
            New-SecureStoreSecret -KeyName 'test' -SecretFileName 'secret.json' -Password 'value' -WhatIf
            Assert-MockCalled -CommandName Write-SecureStoreFile -ModuleName SecureStore -Times 0 -Scope It
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
            Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' | Should Be 'P@ssw0rd!'
        }
    }

    It 'returns PSCredential using explicit paths as per help example' {
        InModuleScope SecureStore {
            $credential = Get-SecureStoreSecret -KeyPath './bin/Api.bin' -SecretPath './secrets/api.secret' -AsCredential -UserName 'api-user'
            $credential.UserName | Should Be 'api-user'
            $credential.GetNetworkCredential().Password | Should Be 'P@ssw0rd!'
        }
    }

    It 'falls back to the legacy secret folder when the preferred path is empty' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*secrets*prod.secret' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*secret*prod.secret' -and $LiteralPath -notlike '*securestore*secrets*prod.secret' } -MockWith { return $true }
            Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' | Should Be 'P@ssw0rd!'
        }
    }

    It 'supports path-like KeyName and SecretFileName inputs' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*secrets*prod.secret' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*secret*prod.secret' -and $LiteralPath -notlike '*securestore*secrets*prod.secret' } -MockWith { return $true }
            Get-SecureStoreSecret -KeyName '/securestore/bin/Database.bin' -SecretFileName '/securestore/secret/prod.secret' | Should Be 'P@ssw0rd!'
        }
    }

    It 'throws a friendly error when the key file is missing' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*bin*Database.bin' } -MockWith { return $false }
            { Get-SecureStoreSecret -KeyName 'Database' -SecretFileName 'prod.secret' } | Should Throw
        }
    }
}

Describe 'New-SecureStoreCertificate' {
    BeforeEach {
        $script:CertificateTestPath = Join-Path -Path $env:TEMP -ChildPath ("SecureStore_Pester_" + [guid]::NewGuid().Guid)
    }

    AfterEach {
        if ($script:CertificateTestPath -and (Test-Path -LiteralPath $script:CertificateTestPath)) {
            Remove-Item -LiteralPath $script:CertificateTestPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'creates a certificate and exports PEM as documented' {
        $result = New-SecureStoreCertificate -CertificateName 'WebApp' -Password 'Sup3rPfx!' -DnsName 'web.local' -FolderPath $script:CertificateTestPath -ExportPem -Confirm:$false
        $result.CertificateName | Should Be 'WebApp'
        Test-Path -LiteralPath (Join-Path -Path $script:CertificateTestPath -ChildPath 'certs\WebApp.pfx') | Should Be $true
        Test-Path -LiteralPath (Join-Path -Path $script:CertificateTestPath -ChildPath 'certs\WebApp.pem') | Should Be $true
        $pemContent = Get-Content -LiteralPath (Join-Path -Path $script:CertificateTestPath -ChildPath 'certs\WebApp.pem') -Raw
        $pemContent | Should Match 'BEGIN CERTIFICATE'
    }

    It 'supports the ECDSA help example' {
        $secure = [System.Security.SecureString]::new()
        foreach ($ch in 'Sup3rPfx!'.ToCharArray()) { $secure.AppendChar($ch) }
        $secure.MakeReadOnly()
        New-SecureStoreCertificate -CertificateName 'Api' -Password $secure -FolderPath $script:CertificateTestPath -Algorithm ECDSA -CurveName nistP256 -ValidityYears 2 -Confirm:$false
        Test-Path -LiteralPath (Join-Path -Path $script:CertificateTestPath -ChildPath 'certs\Api.pfx') | Should Be $true
    }

    It 'exports PEM for ECDSA certificates' {
        $result = New-SecureStoreCertificate -CertificateName 'Ecc' -Password 'Sup3rPfx!' -FolderPath $script:CertificateTestPath -Algorithm ECDSA -CurveName nistP256 -ExportPem -Confirm:$false 3>$null
        $result.Paths.Pem | Should Match 'Ecc.pem'
        $pemContent = Get-Content -LiteralPath $result.Paths.Pem -Raw
        $pemContent | Should Match 'BEGIN CERTIFICATE'
    }

    It 'honours -WhatIf to avoid export' {
        New-SecureStoreCertificate -CertificateName 'Skip' -Password 'pass123!' -FolderPath $script:CertificateTestPath -WhatIf
        Test-Path -LiteralPath (Join-Path -Path $script:CertificateTestPath -ChildPath 'certs\Skip.pfx') | Should Be $false
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
            ($result.Keys -contains 'Database.bin') | Should Be $true
            ($result.Secrets -contains 'prod.secret') | Should Be $true
            $result.Certificates.Count | Should Be 1
            $result.Certificates[0].ExpiresSoon | Should Be $true
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
            ($result.Secrets -contains 'prod.secret') | Should Be $true
            ($result.Secrets -contains 'legacy.secret') | Should Be $true
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
            $status.Ready | Should Be $true
            $status.Locations.InSync | Should Be $true
        }
    }

    It 'detects missing folders' {
        InModuleScope SecureStore {
            Mock -CommandName Test-Path -ModuleName SecureStore -MockWith { return $true }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*secrets' } -MockWith { return $false }
            Mock -CommandName Test-Path -ModuleName SecureStore -ParameterFilter { $LiteralPath -like '*securestore*secret' -and $LiteralPath -notlike '*securestore*secrets' } -MockWith { return $false }
            $status = Test-SecureStoreEnvironment -FolderPath '/securestore'
            $status.Ready | Should Be $false
            $status.Paths.SecretExists | Should Be $false
        }
    }
}

Describe 'Windows Credential Manager commands' {
    BeforeEach {
        InModuleScope SecureStore {
            $script:CredentialStore = @{}
            Mock -CommandName Read-SecureStoreCredentialManagerItem -ModuleName SecureStore -MockWith {
                param([string]$TargetName)

                if (-not $script:CredentialStore.ContainsKey($TargetName)) {
                    return $null
                }

                $entry = $script:CredentialStore[$TargetName]
                return [PSCustomObject]@{
                    TargetName  = $TargetName
                    UserName    = $entry.UserName
                    Comment     = $entry.Comment
                    Type        = 1
                    Persistence = ConvertTo-SecureStoreCredentialPersistenceName -Persistence $entry.Persistence
                    Secret      = (ConvertTo-SecureStoreSecureString -InputObject $entry.Secret)
                }
            }
            Mock -CommandName Write-SecureStoreCredentialManagerItem -ModuleName SecureStore -MockWith {
                param(
                    [string]$TargetName,
                    [string]$UserName,
                    [System.Security.SecureString]$Secret,
                    [int]$Persistence,
                    [string]$Comment
                )

                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
                try {
                    $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                }
                finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }

                $script:CredentialStore[$TargetName] = [PSCustomObject]@{
                    UserName    = $UserName
                    Secret      = $plainText
                    Persistence = $Persistence
                    Comment     = $Comment
                }
            }
            Mock -CommandName Invoke-SecureStoreCredentialManagerDelete -ModuleName SecureStore -MockWith {
                param([string]$TargetName)

                if (-not $script:CredentialStore.ContainsKey($TargetName)) {
                    return $false
                }

                $script:CredentialStore.Remove($TargetName)
                return $true
            }
            Mock -CommandName Get-SecureStoreCredentialManagerItem -ModuleName SecureStore -MockWith {
                param([string]$Filter)

                $targets = $script:CredentialStore.Keys
                if (-not [string]::IsNullOrWhiteSpace($Filter)) {
                    $wildcard = [System.Management.Automation.WildcardPattern]::new($Filter, [System.Management.Automation.WildcardOptions]::IgnoreCase)
                    $targets = @($targets | Where-Object { $wildcard.IsMatch($_) })
                }

                foreach ($target in $targets) {
                    $entry = $script:CredentialStore[$target]
                    [PSCustomObject]@{
                        TargetName  = $target
                        UserName    = $entry.UserName
                        Persistence = ConvertTo-SecureStoreCredentialPersistenceName -Persistence $entry.Persistence
                        Comment     = $entry.Comment
                        Secret      = (ConvertTo-SecureStoreSecureString -InputObject $entry.Secret)
                    }
                }
            }
        }
    }

    It 'creates and retrieves a credential as PSCredential' {
        InModuleScope SecureStore {
            New-SecureStoreCredential -TargetName 'SecureStore:Unit:Api' -UserName 'api-user' -Password 'token-value' -Comment 'unit test' -Force
            $credential = Get-SecureStoreCredential -TargetName 'SecureStore:Unit:Api' -AsCredential

            $credential | Should BeOfType ([System.Management.Automation.PSCredential])
            $credential.UserName | Should Be 'api-user'
            $credential.GetNetworkCredential().Password | Should Be 'token-value'
        }
    }

    It 'prevents accidental overwrite unless Force is supplied' {
        InModuleScope SecureStore {
            New-SecureStoreCredential -TargetName 'SecureStore:Unit:Existing' -UserName 'first' -Password 'one'
            { New-SecureStoreCredential -TargetName 'SecureStore:Unit:Existing' -UserName 'second' -Password 'two' } | Should Throw

            New-SecureStoreCredential -TargetName 'SecureStore:Unit:Existing' -UserName 'second' -Password 'two' -Force
            Get-SecureStoreCredential -TargetName 'SecureStore:Unit:Existing' -AsPlainText | Should Be 'two'
        }
    }

    It 'updates, lists, and removes credentials' {
        InModuleScope SecureStore {
            Set-SecureStoreCredential -TargetName 'SecureStore:Unit:Mutable' -UserName 'user-a' -Password 'old'
            Set-SecureStoreCredential -TargetName 'SecureStore:Unit:Mutable' -UserName 'user-b' -Password 'new' -Persistence Session

            $item = Get-SecureStoreCredential -TargetName 'SecureStore:Unit:Mutable'
            $item.UserName | Should Be 'user-b'
            $item.Persistence | Should Be 'Session'
            $item.Secret | Should BeOfType ([System.Security.SecureString])

            $list = Get-SecureStoreCredentialList -Filter 'SecureStore:Unit:*'
            ($list.TargetName -contains 'SecureStore:Unit:Mutable') | Should Be $true
            ($list | Get-Member -Name Secret -ErrorAction SilentlyContinue) | Should BeNullOrEmpty

            Remove-SecureStoreCredential -TargetName 'SecureStore:Unit:Mutable' -PassThru -Confirm:$false | Should Be $true
            { Get-SecureStoreCredential -TargetName 'SecureStore:Unit:Mutable' } | Should Throw
        }
    }

    It 'honours WhatIf for create, set, and remove operations' {
        InModuleScope SecureStore {
            New-SecureStoreCredential -TargetName 'SecureStore:Unit:WhatIfNew' -UserName 'user' -Password 'secret' -WhatIf
            Set-SecureStoreCredential -TargetName 'SecureStore:Unit:WhatIfSet' -UserName 'user' -Password 'secret' -WhatIf
            Remove-SecureStoreCredential -TargetName 'SecureStore:Unit:WhatIfRemove' -WhatIf

            Assert-MockCalled -CommandName Write-SecureStoreCredentialManagerItem -ModuleName SecureStore -Times 0 -Scope It
            Assert-MockCalled -CommandName Invoke-SecureStoreCredentialManagerDelete -ModuleName SecureStore -Times 0 -Scope It
        }
    }
}

