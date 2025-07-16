@{
    # Module manifest for SecureStore
    RootModule = 'SecureStore.psm1'
    ModuleVersion = '2.0.0'
    GUID = '12345678-1234-1234-1234-123456789012'
    Author = 'SecureStore Module'
    CompanyName = 'SecureStore'
    Copyright = '(c) SecureStore Module. All rights reserved.'
    Description = 'Centralized local secret management and certificate generation with standardized folder structure'
    
    # Minimum PowerShell version
    PowerShellVersion = '5.1'
    
    # Functions to export from this module
    FunctionsToExport = @(
        'New-SecureStoreSecret',
        'Get-SecureStoreSecret', 
        'Get-SecureStoreList',
        'Test-SecureStoreEnvironment',
        'New-SecureStoreCertificate'
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
        'SecureStore.psm1',
        'Sync-SecureStoreWorkingDirectory.ps1',
        'New-SecureStoreSecret.ps1',
        'Get-SecureStoreSecret.ps1',
        'Get-SecureStoreList.ps1',
        'Test-SecureStoreEnvironment.ps1',
        'New-SecureStoreCertificate.ps1'
    )
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for online galleries
            Tags = @('Security', 'Secrets', 'Certificates', 'Encryption', 'LocalStorage', 'AES', 'PKI')
            
            # Release notes for this module
            ReleaseNotes = 'Version 2.0.0: Centralized storage, standardized folder structure, integrated certificate generation'
            
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