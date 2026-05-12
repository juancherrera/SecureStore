@{
    # Module manifest for SecureStore
    RootModule = 'SecureStore.psm1'
    ModuleVersion = '2.1.0'
    GUID = 'fc9f995d-c787-464a-8b37-70c083a5558d'
    Author = 'SecureStore Module'
    CompanyName = 'SecureStore'
    Copyright = '(c) SecureStore Module. All rights reserved.'
    Description = 'Centralized local secret management, Windows Credential Manager integration, and certificate generation with standardized folder structure'

    # Minimum PowerShell version
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    # Functions to export from this module
    FunctionsToExport = @(
        'New-SecureStoreSecret',
        'Get-SecureStoreSecret',
        'Get-SecureStoreList',
        'Test-SecureStoreEnvironment',
        'New-SecureStoreCertificate',
        'New-SecureStoreCredential',
        'Set-SecureStoreCredential',
        'Get-SecureStoreCredential',
        'Get-SecureStoreCredentialList',
        'Remove-SecureStoreCredential'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # DSC resources to export from this module
    DscResourcesToExport = @()

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @(
        'SecureStore.psd1',
        'SecureStore.psm1',
        'Sync-SecureStoreWorkingDirectory.ps1',
        'New-SecureStoreSecret.ps1',
        'Get-SecureStoreSecret.ps1',
        'Get-SecureStoreList.ps1',
        'Test-SecureStoreEnvironment.ps1',
        'New-SecureStoreCertificate.ps1',
        'New-SecureStoreCredential.ps1',
        'Set-SecureStoreCredential.ps1',
        'Get-SecureStoreCredential.ps1',
        'Get-SecureStoreCredentialList.ps1',
        'Remove-SecureStoreCredential.ps1',
        'README.md',
        'LICENSE'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for online galleries
            Tags = @('Security', 'Secrets', 'Certificates', 'Encryption', 'LocalStorage', 'AES', 'PKI', 'CredentialManager')

            # Release notes for this module
            ReleaseNotes = 'Version 2.1.0: Adds Windows Credential Manager support with create, update, retrieve, list, and remove commands. Retains centralized encrypted storage and certificate generation.'

            # Project website
            ProjectUri = 'https://github.com/juancherrera/SecureStore'

            # License metadata for PowerShell Gallery
            LicenseUri = 'https://github.com/juancherrera/SecureStore/blob/main/LICENSE'

            # Prerelease string for this module
            Prerelease = ''

            # Flag to indicate whether the module requires explicit acceptance
            RequireLicenseAcceptance = $false

            # External dependent modules
            ExternalModuleDependencies = @()
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = ''

    # Default prefix for commands exported from this module
    DefaultCommandPrefix = ''
}
