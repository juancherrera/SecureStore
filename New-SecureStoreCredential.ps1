<#
.SYNOPSIS
Creates a Windows Credential Manager generic credential.

.DESCRIPTION
New-SecureStoreCredential stores a secret in Windows Credential Manager as a generic
credential. It refuses to overwrite an existing target unless -Force is supplied and
honours ShouldProcess for -WhatIf and -Confirm.

.PARAMETER TargetName
Credential Manager target name.

.PARAMETER UserName
Username associated with the credential.

.PARAMETER Password
Secret value to store. Accepts plain text or SecureString.

.PARAMETER Persistence
Credential persistence scope. Defaults to LocalMachine.

.PARAMETER Comment
Optional comment stored with the credential.

.PARAMETER Force
Overwrite an existing credential with the same target name.

.OUTPUTS
PSCustomObject describing the stored credential metadata.

.EXAMPLE
New-SecureStoreCredential -TargetName 'SecureStore:Api' -UserName 'api-user' -Password 'token' -Force
#>
function New-SecureStoreCredential {
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
        [string]$Comment,

        [Parameter()]
        [switch]$Force
    )

    process {
        $securePassword = $null
        try {
            $existing = Read-SecureStoreCredentialManagerItem -TargetName $TargetName
            if ($existing) {
                if ($existing.Secret) {
                    $existing.Secret.Dispose()
                }

                if (-not $Force.IsPresent) {
                    throw [System.InvalidOperationException]::new("Credential '$TargetName' already exists. Use -Force to overwrite it.")
                }
            }

            if (-not $PSCmdlet.ShouldProcess($TargetName, 'Create Windows Credential Manager credential')) {
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
            throw [System.InvalidOperationException]::new("Failed to create Windows credential '$TargetName'.", $_.Exception)
        }
        finally {
            if ($securePassword) {
                $securePassword.Dispose()
            }
        }
    }
}
