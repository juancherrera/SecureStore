#
# SecureStore Module v2.0
# Centralized local secret management and certificate generation
# Default location: C:\SecureStore with standardized folder structure
#

# Set module-level variables
$script:DefaultSecureStorePath = "C:\SecureStore"

# Import private helper functions
. "$PSScriptRoot\Sync-SecureStoreWorkingDirectory.ps1"

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

# Create default SecureStore structure on module load if it doesn't exist
if (-not (Test-Path $script:DefaultSecureStorePath)) {
    try {
        Sync-SecureStoreWorkingDirectory -BasePath $script:DefaultSecureStorePath | Out-Null
        Write-Verbose "Created default SecureStore structure at $script:DefaultSecureStorePath"
    } catch {
        Write-Warning "Could not create default SecureStore structure: $($_.Exception.Message)"
    }
}