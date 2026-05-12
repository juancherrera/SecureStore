<#
.SYNOPSIS
Removes a Windows Credential Manager generic credential.

.DESCRIPTION
Remove-SecureStoreCredential deletes a generic credential from Windows Credential Manager.
It supports ShouldProcess and can return whether a credential was removed via -PassThru.

.EXAMPLE
Remove-SecureStoreCredential -TargetName 'SecureStore:Api' -Confirm:$false
#>
function Remove-SecureStoreCredential {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetName,

        [Parameter()]
        [switch]$PassThru
    )

    process {
        try {
            if (-not $PSCmdlet.ShouldProcess($TargetName, 'Remove Windows Credential Manager credential')) {
                return
            }

            $removed = Invoke-SecureStoreCredentialManagerDelete -TargetName $TargetName
            if ($PassThru.IsPresent) {
                return $removed
            }
        }
        catch {
            throw [System.InvalidOperationException]::new("Failed to remove Windows credential '$TargetName'.", $_.Exception)
        }
    }
}
