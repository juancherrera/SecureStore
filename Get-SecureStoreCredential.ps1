<#
.SYNOPSIS
Retrieves a Windows Credential Manager generic credential.

.DESCRIPTION
Get-SecureStoreCredential reads a generic credential from Windows Credential Manager.
By default it returns metadata plus a SecureString. Use -AsCredential for PSCredential
or -AsPlainText when plain text output is explicitly required.

.EXAMPLE
Get-SecureStoreCredential -TargetName 'SecureStore:Api' -AsCredential
#>
function Get-SecureStoreCredential {
    [CmdletBinding(DefaultParameterSetName = 'SecureString')]
    [OutputType([pscustomobject], ParameterSetName = 'SecureString')]
    [OutputType([System.Management.Automation.PSCredential], ParameterSetName = 'Credential')]
    [OutputType([string], ParameterSetName = 'PlainText')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetName,

        [Parameter(ParameterSetName = 'Credential')]
        [switch]$AsCredential,

        [Parameter(ParameterSetName = 'PlainText')]
        [switch]$AsPlainText
    )

    process {
        $item = $null
        try {
            $item = Read-SecureStoreCredentialManagerItem -TargetName $TargetName
            if (-not $item) {
                throw [System.Management.Automation.ItemNotFoundException]::new("Credential '$TargetName' was not found.")
            }

            if ($PSCmdlet.ParameterSetName -eq 'Credential') {
                return [System.Management.Automation.PSCredential]::new($item.UserName, $item.Secret.Copy())
            }

            if ($PSCmdlet.ParameterSetName -eq 'PlainText') {
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($item.Secret)
                try {
                    return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                }
                finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }

            [PSCustomObject]@{
                TargetName  = $item.TargetName
                UserName    = $item.UserName
                Persistence = $item.Persistence
                Comment     = $item.Comment
                Secret      = $item.Secret.Copy()
            }
        }
        catch {
            throw [System.InvalidOperationException]::new("Failed to retrieve Windows credential '$TargetName'.", $_.Exception)
        }
        finally {
            if ($item -and $item.Secret) {
                $item.Secret.Dispose()
            }
        }
    }
}
