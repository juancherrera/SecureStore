<#
.SYNOPSIS
Creates or updates a Windows Credential Manager generic credential.

.DESCRIPTION
Set-SecureStoreCredential writes a generic Windows Credential Manager entry for the
specified target name. Existing credentials are updated in place.

.EXAMPLE
Set-SecureStoreCredential -TargetName 'SecureStore:Api' -UserName 'api-user' -Password 'new-token'
#>
function Set-SecureStoreCredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'The parameter accepts SecureString and string for consistency with existing SecureStore commands; values are converted to SecureString before native Credential Manager calls.')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Password,

        [Parameter()]
        [ValidateSet('Session', 'LocalMachine', 'Enterprise')]
        [string]$Persistence = 'LocalMachine',

        [Parameter()]
        [AllowNull()]
        [string]$Comment
    )

    process {
        $securePassword = $null
        try {
            if (-not $PSCmdlet.ShouldProcess($TargetName, 'Create or update Windows Credential Manager credential')) {
                return
            }

            $persistenceValue = @{
                Session      = 1
                LocalMachine = 2
                Enterprise   = 3
            }[$Persistence]

            $securePassword = ConvertTo-SecureStoreSecureString -InputObject $Password
            Write-SecureStoreCredentialManagerItem -TargetName $TargetName -UserName $UserName -Secret $securePassword -Persistence $persistenceValue -Comment $Comment

            [PSCustomObject]@{
                TargetName  = $TargetName
                UserName    = $UserName
                Persistence = $Persistence
                Comment     = $Comment
            }
        }
        catch {
            throw [System.InvalidOperationException]::new("Failed to set Windows credential '$TargetName'.", $_.Exception)
        }
        finally {
            if ($securePassword) {
                $securePassword.Dispose()
            }
        }
    }
}
