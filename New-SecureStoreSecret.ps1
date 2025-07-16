function New-SecureStoreSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretFileName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [string]$FolderPath = "C:\SecureStore"
    )

    begin {
        # Import private helper if not already loaded
        if (-not (Get-Command "Sync-SecureStoreWorkingDirectory" -ErrorAction SilentlyContinue)) {
            . "$PSScriptRoot\Sync-SecureStoreWorkingDirectory.ps1"
        }
    }

    process {
        try {
            # Create folder structure and get paths
            $paths = Sync-SecureStoreWorkingDirectory -BasePath $FolderPath
            
            # Define file paths
            $keyFilePath = [System.IO.Path]::Combine($paths.BinPath, "$KeyName.bin")
            $secretFilePath = [System.IO.Path]::Combine($paths.SecretPath, $SecretFileName)

            # Generate or read encryption key
            if (-not (Test-Path $keyFilePath)) {
                Write-Verbose "Generating new 256-bit AES key"
                $encryptionKey = New-Object byte[] 32
                $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
                $rng.GetBytes($encryptionKey)
                $rng.Dispose()
                [System.IO.File]::WriteAllBytes($keyFilePath, $encryptionKey)
            }

            # Encrypt the password
            $encryptionKey = [System.IO.File]::ReadAllBytes($keyFilePath)
            $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $encryptedPassword = ConvertFrom-SecureString -SecureString $securePassword -Key $encryptionKey

            # Save encrypted password
            [System.IO.File]::WriteAllText($secretFilePath, $encryptedPassword, [System.Text.Encoding]::UTF8)

            Write-Host "Secret '$SecretFileName' created with key '$KeyName' in $($paths.BasePath)"

        } catch {
            Write-Error "Failed to create secret: $($_.Exception.Message)"
        }
    }
}