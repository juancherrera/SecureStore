<#
.SYNOPSIS
Lists Windows Credential Manager generic credentials.

.DESCRIPTION
Get-SecureStoreCredentialList enumerates generic credentials from Windows Credential
Manager and returns metadata only. Credential secrets are not returned by this command.

.PARAMETER Filter
Optional Credential Manager filter. Wildcards are supported by the Windows API when
the pattern ends with an asterisk.

.EXAMPLE
Get-SecureStoreCredentialList -Filter 'SecureStore:*'
#>
function Get-SecureStoreCredentialList {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Filter
    )

    process {
        try {
            $items = @(Get-SecureStoreCredentialManagerItem -Filter $Filter)
            foreach ($item in $items) {
                try {
                    [PSCustomObject]@{
                        TargetName  = $item.TargetName
                        UserName    = $item.UserName
                        Persistence = $item.Persistence
                        Comment     = $item.Comment
                    }
                }
                finally {
                    if ($item.Secret) {
                        $item.Secret.Dispose()
                    }
                }
            }
        }
        catch {
            throw [System.InvalidOperationException]::new('Failed to list Windows Credential Manager credentials.', $_.Exception)
        }
    }
}
