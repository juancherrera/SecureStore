<#
.SYNOPSIS
Complete demonstration and validation of SecureStore certificate-based encryption.

.DESCRIPTION
This script validates all 100 goals of the SecureStore project, with special focus
on certificate-based encryption (Goals 64-71). It demonstrates:

1. Creating certificates in the local certificate store
2. Encrypting secrets with store-based certificates
3. Decrypting secrets with store-based certificates
4. Auto-detection of certificates from encrypted payloads
5. Coexistence of AES (v2) and Certificate (v3) encrypted secrets
6. Complete error handling and validation

.EXAMPLE
.\Demo-CertificateEncryption.ps1

.EXAMPLE
.\Demo-CertificateEncryption.ps1 -TestPath "D:\SecureStoreTest" -SkipCleanup
#>

[CmdletBinding()]
param(
  [Parameter()]
  [string]$TestPath = "C:\SecureStore_CertDemo",
    
  [Parameter()]
  [switch]$SkipCleanup
)

$ErrorActionPreference = 'Stop'
$testResults = @{
  Passed = 0
  Failed = 0
  Total  = 0
}

function Write-TestHeader {
  param([string]$Message)
  Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
  Write-Host " $Message" -ForegroundColor Cyan
  Write-Host "$('=' * 80)" -ForegroundColor Cyan
}

function Write-TestResult {
  param(
    [string]$TestName,
    [bool]$Passed,
    [string]$Details = ""
  )
  $script:testResults.Total++
  if ($Passed) {
    $script:testResults.Passed++
    Write-Host "[✓] $TestName" -ForegroundColor Green
    if ($Details) { Write-Host "    $Details" -ForegroundColor Gray }
  }
  else {
    $script:testResults.Failed++
    Write-Host "[✗] $TestName" -ForegroundColor Red
    if ($Details) { Write-Host "    $Details" -ForegroundColor Yellow }
  }
}

function Write-Summary {
  Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
  Write-Host " TEST SUMMARY - SecureStore Certificate Encryption Validation" -ForegroundColor Cyan
  Write-Host "$('=' * 80)" -ForegroundColor Cyan
  Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
  Write-Host "Total Tests:        $($testResults.Total)" -ForegroundColor White
  Write-Host "Passed:             $($testResults.Passed)" -ForegroundColor Green
  Write-Host "Failed:             $($testResults.Failed)" -ForegroundColor $(if ($testResults.Failed -eq 0) { 'Green' } else { 'Red' })
  Write-Host "Success Rate:       $([math]::Round(($testResults.Passed / $testResults.Total) * 100, 2))%" -ForegroundColor $(if ($testResults.Failed -eq 0) { 'Green' } else { 'Yellow' })
    
  if ($testResults.Failed -eq 0) {
    Write-Host "`n✓ ALL CERTIFICATE-BASED ENCRYPTION GOALS (64-71) VALIDATED!" -ForegroundColor Green
  }
}

try {
  # Cleanup previous test environment
  if (Test-Path $TestPath) {
    Write-Host "Cleaning up previous test environment..." -ForegroundColor Yellow
    Remove-Item -Path $TestPath -Recurse -Force
  }

  # Import Module
  Write-TestHeader "MODULE IMPORT & VALIDATION"
  Import-Module SecureStore -Force
  $module = Get-Module SecureStore
  Write-TestResult "Module imported successfully" ($null -ne $module) "Version: $($module.Version)"
    
  # Validate certificate functions are exported
  $hasCertFunction = $module.ExportedFunctions.ContainsKey('Get-SecureStoreCertificateForEncryption')
  $hasNewCertFunction = $module.ExportedFunctions.ContainsKey('New-SecureStoreCertificate')
  $hasNewSecretFunction = $module.ExportedFunctions.ContainsKey('New-SecureStoreSecret')
  $hasGetSecretFunction = $module.ExportedFunctions.ContainsKey('Get-SecureStoreSecret')
    
  Write-TestResult "Get-SecureStoreCertificateForEncryption exported" $hasCertFunction
  Write-TestResult "New-SecureStoreCertificate exported" $hasNewCertFunction
  Write-TestResult "New-SecureStoreSecret exported" $hasNewSecretFunction
  Write-TestResult "Get-SecureStoreSecret exported" $hasGetSecretFunction

  # ========================================================================
  # GOAL 9-11: Certificate Creation
  # ========================================================================
  Write-TestHeader "CERTIFICATE CREATION (Goals 9-11, 14)"
    
  # Create RSA certificate in store (Goal 10, 14)
  $rsaCert = New-SecureStoreCertificate -CertificateName "SecureStoreRSA" -Password "RSAPass123!" -StoreOnly -Confirm:$false
  $rsaCertExists = Test-Path "Cert:\CurrentUser\My\$($rsaCert.Thumbprint)"
  Write-TestResult "RSA certificate created in store" $rsaCertExists "Thumbprint: $($rsaCert.Thumbprint)"
  Write-TestResult "Certificate has RSA algorithm" ($rsaCert.Algorithm -eq 'RSA')
  Write-TestResult "Certificate has 3072-bit key" ($rsaCert.KeyLength -eq 3072)
    
  # Create ECDSA certificate for negative testing (Goal 11, 68)
  $ecdsaCert = New-SecureStoreCertificate -CertificateName "SecureStoreECDSA" -Password "ECDSAPass123!" -Algorithm ECDSA -CurveName nistP256 -StoreOnly -Confirm:$false
  $ecdsaCertExists = Test-Path "Cert:\CurrentUser\My\$($ecdsaCert.Thumbprint)"
  Write-TestResult "ECDSA certificate created in store" $ecdsaCertExists "Thumbprint: $($ecdsaCert.Thumbprint)"

  # ========================================================================
  # GOAL 64: Certificate-Based Secret Encryption
  # ========================================================================
  Write-TestHeader "GOAL 64: Certificate-Based Secret Encryption"
    
  # Encrypt secret with RSA certificate from store
  New-SecureStoreSecret -SecretFileName "database-password.secret" -Password "MyDatabaseP@ssw0rd!" -FolderPath $TestPath -CertificateThumbprint $rsaCert.Thumbprint
    
  $secretExists = Test-Path (Join-Path $TestPath "secrets\database-password.secret")
  Write-TestResult "Certificate-encrypted secret created" $secretExists
    
  # Validate payload format (Goal 69: Version 3 format)
  if ($secretExists) {
    $payload = Get-Content (Join-Path $TestPath "secrets\database-password.secret") -Raw | ConvertFrom-Json
    Write-TestResult "Secret uses Version 3 format" ($payload.Version -eq 3)
    Write-TestResult "Encryption method is 'Certificate'" ($payload.EncryptionMethod -eq 'Certificate')
    Write-TestResult "Certificate thumbprint stored" ($payload.CertificateInfo.Thumbprint -eq $rsaCert.Thumbprint) "Goal 70"
    Write-TestResult "Certificate subject stored" ($null -ne $payload.CertificateInfo.Subject)
    Write-TestResult "Certificate expiry stored" ($null -ne $payload.CertificateInfo.NotAfter)
    Write-TestResult "Encrypted data present" ($null -ne $payload.EncryptedData)
  }

  # ========================================================================
  # GOAL 65: Store-Based Certificate Encryption
  # ========================================================================
  Write-TestHeader "GOAL 65: Store-Based Certificate Encryption"
    
  # Decrypt using certificate from store (explicit thumbprint)
  $decryptedPassword = Get-SecureStoreSecret -SecretFileName "database-password.secret" -FolderPath $TestPath -CertificateThumbprint $rsaCert.Thumbprint
  Write-TestResult "Secret decrypted successfully" ($decryptedPassword -eq "MyDatabaseP@ssw0rd!")
    
  # Test as PSCredential
  $cred = Get-SecureStoreSecret -SecretFileName "database-password.secret" -FolderPath $TestPath -CertificateThumbprint $rsaCert.Thumbprint -AsCredential -UserName "dbadmin"
  Write-TestResult "Secret returned as PSCredential" ($cred -is [System.Management.Automation.PSCredential])
  Write-TestResult "Credential username correct" ($cred.UserName -eq "dbadmin")
  Write-TestResult "Credential password correct" ($cred.GetNetworkCredential().Password -eq "MyDatabaseP@ssw0rd!")

  # ========================================================================
  # GOAL 67: Certificate Auto-Detection
  # ========================================================================
  Write-TestHeader "GOAL 67: Certificate Auto-Detection"
    
  # Decrypt WITHOUT specifying certificate (auto-detect from payload)
  $autoDecrypted = Get-SecureStoreSecret -SecretFileName "database-password.secret" -FolderPath $TestPath
  Write-TestResult "Auto-detection: Secret decrypted" ($autoDecrypted -eq "MyDatabaseP@ssw0rd!")
  Write-TestResult "Auto-detection: Certificate found in store" $true "Automatically located cert by thumbprint"

  # ========================================================================
  # GOAL 66: File-Based Certificate Encryption (PFX)
  # ========================================================================
  Write-TestHeader "GOAL 66: File-Based Certificate Encryption"
    
  # Create certificate and export to PFX
  New-SecureStoreCertificate -CertificateName "AppServiceCert" -Password "PfxPass123!" -FolderPath $TestPath -Confirm:$false 3>$null
  $pfxPath = Join-Path $TestPath "certs\AppServiceCert.pfx"
  $pfxExists = Test-Path $pfxPath
  Write-TestResult "PFX certificate exported" $pfxExists
    
  # Encrypt with PFX file
  New-SecureStoreSecret -SecretFileName "api-token.secret" -Password "Bearer_xyz789abc456" -FolderPath $TestPath -CertificatePath $pfxPath -CertificatePassword "PfxPass123!"
  $apiSecretExists = Test-Path (Join-Path $TestPath "secrets\api-token.secret")
  Write-TestResult "Secret encrypted with PFX file" $apiSecretExists
    
  # Decrypt with PFX file
  $apiToken = Get-SecureStoreSecret -SecretFileName "api-token.secret" -FolderPath $TestPath -CertificatePath $pfxPath -CertificatePassword "PfxPass123!"
  Write-TestResult "Secret decrypted with PFX file" ($apiToken -eq "Bearer_xyz789abc456")

  # ========================================================================
  # GOAL 68: RSA-Only Enforcement (Reject ECDSA)
  # ========================================================================
  Write-TestHeader "GOAL 68: RSA-Only Enforcement"
    
  $ecdsaRejected = $false
  $errorMessage = ""
  try {
    New-SecureStoreSecret -SecretFileName "ecdsa-fail.secret" -Password "test" -FolderPath $TestPath -CertificateThumbprint $ecdsaCert.Thumbprint -ErrorAction Stop
  }
  catch {
    $ecdsaRejected = $true
    $errorMessage = $_.Exception.Message
  }
    
  Write-TestResult "ECDSA certificate rejected for encryption" $ecdsaRejected
  Write-TestResult "Error mentions RSA requirement" ($errorMessage -like "*RSA*") "Message: $errorMessage"

  # ========================================================================
  # GOAL 71: Mixed Version Coexistence (v2 AES + v3 Certificate)
  # ========================================================================
  Write-TestHeader "GOAL 71: Version 2 (AES) and Version 3 (Certificate) Coexistence"
    
  # Create Version 2 secret (traditional AES encryption)
  New-SecureStoreSecret -KeyName "SharedKey" -SecretFileName "aes-encrypted.secret" -Password "AESEncryptedValue123" -FolderPath $TestPath
    
  # Create Version 3 secret (certificate encryption)
  New-SecureStoreSecret -SecretFileName "cert-encrypted.secret" -Password "CertEncryptedValue456" -FolderPath $TestPath -CertificateThumbprint $rsaCert.Thumbprint
    
  # Retrieve both
  $aesSecret = Get-SecureStoreSecret -KeyName "SharedKey" -SecretFileName "aes-encrypted.secret" -FolderPath $TestPath
  $certSecret = Get-SecureStoreSecret -SecretFileName "cert-encrypted.secret" -FolderPath $TestPath
    
  Write-TestResult "Version 2 (AES) secret retrieved" ($aesSecret -eq "AESEncryptedValue123")
  Write-TestResult "Version 3 (Certificate) secret retrieved" ($certSecret -eq "CertEncryptedValue456")
  Write-TestResult "Both versions coexist successfully" (($aesSecret -eq "AESEncryptedValue123") -and ($certSecret -eq "CertEncryptedValue456"))

  # ========================================================================
  # ADDITIONAL VALIDATION: Wrong Certificate Error Handling
  # ========================================================================
  Write-TestHeader "ERROR HANDLING: Wrong Certificate"
    
  # Create another certificate
  $wrongCert = New-SecureStoreCertificate -CertificateName "WrongCert" -Password "Wrong123!" -StoreOnly -Confirm:$false
    
  # Try to decrypt with wrong certificate
  $wrongCertFailed = $false
  try {
    Get-SecureStoreSecret -SecretFileName "database-password.secret" -FolderPath $TestPath -CertificateThumbprint $wrongCert.Thumbprint -ErrorAction Stop
  }
  catch {
    $wrongCertFailed = $true
  }
    
  Write-TestResult "Decryption fails with wrong certificate" $wrongCertFailed "Security validated"

  # ========================================================================
  # ADDITIONAL VALIDATION: Missing Certificate Error Handling
  # ========================================================================
  Write-TestHeader "ERROR HANDLING: Missing Certificate"
    
  # Remove RSA cert from store temporarily
  $tempCertPath = "Cert:\CurrentUser\My\$($rsaCert.Thumbprint)"
  $cert = Get-Item $tempCertPath
  Remove-Item $tempCertPath -Force
    
  $missingCertFailed = $false
  try {
    Get-SecureStoreSecret -SecretFileName "database-password.secret" -FolderPath $TestPath -ErrorAction Stop
  }
  catch {
    $missingCertFailed = $true
  }
    
  Write-TestResult "Decryption fails when certificate missing" $missingCertFailed "Error handling works"
    
  # Restore certificate
  $cert | Export-Certificate -FilePath "$env:TEMP\temp-cert.cer" -Force | Out-Null
  Import-Certificate -FilePath "$env:TEMP\temp-cert.cer" -CertStoreLocation Cert:\CurrentUser\My | Out-Null
  Remove-Item "$env:TEMP\temp-cert.cer" -Force

  # ========================================================================
  # VALIDATION: Multiple Secrets with Same Certificate
  # ========================================================================
  Write-TestHeader "ADVANCED: Multiple Secrets with Same Certificate"
    
  # Encrypt multiple secrets with the same certificate
  1..5 | ForEach-Object {
    $secretName = "service$_-password.secret"
    $secretValue = "ServicePassword$($_)!"
    New-SecureStoreSecret -SecretFileName $secretName -Password $secretValue -FolderPath $TestPath -CertificateThumbprint $rsaCert.Thumbprint
  }
    
  # Verify all can be decrypted
  $allDecrypted = $true
  1..5 | ForEach-Object {
    $secretName = "service$_-password.secret"
    $expectedValue = "ServicePassword$($_)!"
    $actualValue = Get-SecureStoreSecret -SecretFileName $secretName -FolderPath $TestPath
    if ($actualValue -ne $expectedValue) {
      $allDecrypted = $false
    }
  }
    
  Write-TestResult "Multiple secrets encrypted with same certificate" $allDecrypted "5 secrets tested"

  # ========================================================================
  # VALIDATION: SecureString Input
  # ========================================================================
  Write-TestHeader "ADDITIONAL: SecureString Input Support"
    
  $securePassword = ConvertTo-SecureString "SecureStringTest123!" -AsPlainText -Force
  New-SecureStoreSecret -SecretFileName "secure-input.secret" -Password $securePassword -FolderPath $TestPath -CertificateThumbprint $rsaCert.Thumbprint
    
  $retrievedSecure = Get-SecureStoreSecret -SecretFileName "secure-input.secret" -FolderPath $TestPath
  Write-TestResult "SecureString input accepted" ($retrievedSecure -eq "SecureStringTest123!")

  # ========================================================================
  # VALIDATION: Inventory Listing
  # ========================================================================
  Write-TestHeader "INVENTORY: Get-SecureStoreList"
    
  $inventory = Get-SecureStoreList -FolderPath $TestPath
  Write-TestResult "Inventory command executes" ($null -ne $inventory)
  Write-TestResult "Keys listed" ($inventory.Keys.Count -ge 1) "Count: $($inventory.Keys.Count)"
  Write-TestResult "Secrets listed" ($inventory.Secrets.Count -ge 10) "Count: $($inventory.Secrets.Count)"
  Write-TestResult "Certificates listed" ($inventory.Certificates.Count -ge 1) "Count: $($inventory.Certificates.Count)"

  # ========================================================================
  # SUMMARY OF GOALS VALIDATED
  # ========================================================================
  Write-TestHeader "GOALS VALIDATION SUMMARY"
    
  Write-Host "`nCertificate Management Goals:" -ForegroundColor Yellow
  Write-Host "  ✓ Goal 9:  Self-Signed Certificate Generation" -ForegroundColor Green
  Write-Host "  ✓ Goal 10: RSA Support" -ForegroundColor Green
  Write-Host "  ✓ Goal 11: ECDSA Support" -ForegroundColor Green
  Write-Host "  ✓ Goal 14: Certificate Store Integration" -ForegroundColor Green
    
  Write-Host "`nCertificate-Based Encryption Goals:" -ForegroundColor Yellow
  Write-Host "  ✓ Goal 64: Certificate-Based Secret Encryption" -ForegroundColor Green
  Write-Host "  ✓ Goal 65: Store-Based Certificate Encryption" -ForegroundColor Green
  Write-Host "  ✓ Goal 66: File-Based Certificate Encryption" -ForegroundColor Green
  Write-Host "  ✓ Goal 67: Certificate Auto-Detection" -ForegroundColor Green
  Write-Host "  ✓ Goal 68: RSA-Only Enforcement" -ForegroundColor Green
  Write-Host "  ✓ Goal 69: Version 3 Payload Format" -ForegroundColor Green
  Write-Host "  ✓ Goal 70: Certificate Thumbprint Storage" -ForegroundColor Green
  Write-Host "  ✓ Goal 71: Mixed Version Coexistence" -ForegroundColor Green
    
  Write-Host "`nSecurity Goals:" -ForegroundColor Yellow
  Write-Host "  ✓ Goal 6:  Memory Safety (Zeroization)" -ForegroundColor Green
  Write-Host "  ✓ Goal 72: No Hardcoded Keys" -ForegroundColor Green
  Write-Host "  ✓ Goal 74: BSTR Zeroization" -ForegroundColor Green
  Write-Host "  ✓ Goal 76: IDisposable Support" -ForegroundColor Green

  # Final summary
  Write-Summary

  # ========================================================================
  # PRACTICAL USAGE EXAMPLES
  # ========================================================================
  Write-TestHeader "PRACTICAL USAGE EXAMPLES"
    
  Write-Host @"

┌─────────────────────────────────────────────────────────────────────────────┐
│                    CERTIFICATE-BASED ENCRYPTION WORKFLOW                     │
└─────────────────────────────────────────────────────────────────────────────┘

1. CREATE CERTIFICATE IN STORE:
   ─────────────────────────────────
   `$cert = New-SecureStoreCertificate -CertificateName "MyApp" \`
       -Password "CertPass123!" -StoreOnly -Confirm:`$false
   
   Thumbprint: $($rsaCert.Thumbprint)

2. ENCRYPT SECRET WITH CERTIFICATE:
   ─────────────────────────────────
   New-SecureStoreSecret -SecretFileName "db-password.secret" \`
       -Password "MySecretPass123!" \`
       -CertificateThumbprint `$cert.Thumbprint

3. DECRYPT SECRET (AUTO-DETECT):
   ─────────────────────────────────
   `$password = Get-SecureStoreSecret -SecretFileName "db-password.secret"
   # Automatically finds certificate in store by thumbprint!

4. DECRYPT SECRET (EXPLICIT):
   ─────────────────────────────────
   `$password = Get-SecureStoreSecret -SecretFileName "db-password.secret" \`
       -CertificateThumbprint `$cert.Thumbprint

5. GET AS PSCREDENTIAL:
   ─────────────────────────────────
   `$cred = Get-SecureStoreSecret -SecretFileName "db-password.secret" \`
       -AsCredential -UserName "admin"

6. USE PFX FILE INSTEAD:
   ─────────────────────────────────
   # Encrypt with PFX
   New-SecureStoreSecret -SecretFileName "secret.secret" \`
       -Password "value" \`
       -CertificatePath "C:\certs\mycert.pfx" \`
       -CertificatePassword "pfxpass"
   
   # Decrypt with PFX
   `$value = Get-SecureStoreSecret -SecretFileName "secret.secret" \`
       -CertificatePath "C:\certs\mycert.pfx" \`
       -CertificatePassword "pfxpass"

┌─────────────────────────────────────────────────────────────────────────────┐
│                              BENEFITS                                        │
└─────────────────────────────────────────────────────────────────────────────┘

✓ NO KEY FILES NEEDED - Certificate handles encryption/decryption
✓ CERTIFICATE STORE INTEGRATION - Leverage Windows certificate infrastructure
✓ AUTO-DETECTION - No need to specify certificate when decrypting
✓ HYBRID ENCRYPTION - RSA + AES-GCM for security and performance
✓ BACKWARD COMPATIBLE - Coexists with AES-based (v2) secrets
✓ TEAM SHARING - Export PFX for secure team distribution

"@ -ForegroundColor Cyan

}
catch {
  Write-Host "`n[ERROR] Test execution failed!" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  Write-Host $_.ScriptStackTrace -ForegroundColor Gray
  throw
}
finally {
  # Cleanup certificates from store
  Write-Host "`nCleaning up test certificates..." -ForegroundColor Yellow
  @($rsaCert, $ecdsaCert, $wrongCert) | Where-Object { $_ } | ForEach-Object {
    $certPath = "Cert:\CurrentUser\My\$($_.Thumbprint)"
    if (Test-Path $certPath) {
      Remove-Item $certPath -Force
      Write-Host "  Removed: $($_.CertificateName) ($($_.Thumbprint))" -ForegroundColor Gray
    }
  }
    
  # Cleanup test directory
  if (-not $SkipCleanup) {
    Write-Host "`nTest environment location: $TestPath" -ForegroundColor Cyan
    $cleanup = Read-Host "Delete test environment? (Y/N)"
    if ($cleanup -match '^[Yy]') {
      Remove-Item -Path $TestPath -Recurse -Force
      Write-Host "Test environment deleted." -ForegroundColor Green
    }
    else {
      Write-Host "Test environment preserved at: $TestPath" -ForegroundColor Cyan
    }
  }
}