<#
.SYNOPSIS
Comprehensive end-to-end test suite for SecureStore module.

.DESCRIPTION
Tests all SecureStore functions with visual output and validation.
Compatible with both PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param(
  [Parameter()]
  [string]$TestPath = "C:\SecureStore_Test"
)

$ErrorActionPreference = 'Stop'
$testsPassed = 0
$testsFailed = 0
$testsTotal = 0
$isPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7

function Write-TestHeader {
  param([string]$Message)
  Write-Host "`n========================================" -ForegroundColor Cyan
  Write-Host " $Message" -ForegroundColor Cyan
  Write-Host "========================================" -ForegroundColor Cyan
}

function Write-TestResult {
  param(
    [string]$TestName,
    [bool]$Passed,
    [string]$Details = ""
  )
  $script:testsTotal++
  if ($Passed) {
    $script:testsPassed++
    Write-Host "[PASS] $TestName" -ForegroundColor Green
    if ($Details) { Write-Host "       $Details" -ForegroundColor Gray }
  }
  else {
    $script:testsFailed++
    Write-Host "[FAIL] $TestName" -ForegroundColor Red
    if ($Details) { Write-Host "       $Details" -ForegroundColor Yellow }
  }
}

function Write-TestSummary {
  Write-Host "`n========================================" -ForegroundColor Cyan
  Write-Host " TEST SUMMARY" -ForegroundColor Cyan
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
  Write-Host "Total Tests: $testsTotal" -ForegroundColor White
  Write-Host "Passed: $testsPassed" -ForegroundColor Green
  Write-Host "Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -eq 0) { 'Green' } else { 'Red' })
  Write-Host "Success Rate: $([math]::Round(($testsPassed / $testsTotal) * 100, 2))%" -ForegroundColor $(if ($testsFailed -eq 0) { 'Green' } else { 'Yellow' })
}

# Clean up test environment if it exists
if (Test-Path $TestPath) {
  Write-Host "Cleaning up previous test environment..." -ForegroundColor Yellow
  Remove-Item -Path $TestPath -Recurse -Force
}

try {
  # TEST 1: Module Import
  Write-TestHeader "TEST 1: Module Import"
  try {
    Import-Module SecureStore -Force
    $module = Get-Module SecureStore
    Write-TestResult "Module imports successfully" ($null -ne $module) "Version: $($module.Version)"
    Write-TestResult "Module has required functions" ($module.ExportedFunctions.Count -ge 5) "Functions: $($module.ExportedFunctions.Count)"
  }
  catch {
    Write-TestResult "Module imports successfully" $false $_.Exception.Message
  }

  # TEST 2: Environment Setup
  Write-TestHeader "TEST 2: Environment Setup"
  try {
    Test-SecureStoreEnvironment -FolderPath $TestPath
    $basePath = Test-Path $TestPath
    $binPath = Test-Path (Join-Path $TestPath "bin")
    $secretPath = Test-Path (Join-Path $TestPath "secrets")
    $certsPath = Test-Path (Join-Path $TestPath "certs")

    Write-TestResult "Base directory created"    $basePath    $TestPath
    Write-TestResult "Bin directory created"     $binPath
    Write-TestResult "Secrets directory created" $secretPath
    Write-TestResult "Certs directory created"   $certsPath
  }
  catch {
    Write-TestResult "Environment setup" $false $_.Exception.Message
  }

  # TEST 3: Create Secrets
  Write-TestHeader "TEST 3: Create Secrets"
  try {
    New-SecureStoreSecret -KeyName "TestApp" -SecretFileName "password.secret" -Password "MyTestPassword123" -FolderPath $TestPath
    $keyExists = Test-Path (Join-Path $TestPath "bin\TestApp.bin")
    $secretExists = Test-Path (Join-Path $TestPath "secrets\password.secret")

    Write-TestResult "Encryption key file created" $keyExists "bin\TestApp.bin"
    Write-TestResult "Secret file created"         $secretExists "secrets\password.secret"
  }
  catch {
    Write-TestResult "Secret creation" $false $_.Exception.Message
  }

  # TEST 4: Create Multiple Secrets with Same Key
  Write-TestHeader "TEST 4: Multiple Secrets with Same Key"
  try {
    New-SecureStoreSecret -KeyName "TestApp" -SecretFileName "api-key.secret" -Password "ApiKey456" -FolderPath $TestPath
    New-SecureStoreSecret -KeyName "TestApp" -SecretFileName "token.secret" -Password "Token789" -FolderPath $TestPath

    $apiKeyExists = Test-Path (Join-Path $TestPath "secrets\api-key.secret")
    $tokenExists = Test-Path (Join-Path $TestPath "secrets\token.secret")

    Write-TestResult "Second secret with same key created" $apiKeyExists
    Write-TestResult "Third secret with same key created"  $tokenExists
  }
  catch {
    Write-TestResult "Multiple secrets creation" $false $_.Exception.Message
  }

  # TEST 5: Retrieve Secrets as Plain Text
  Write-TestHeader "TEST 5: Retrieve Secrets (Plain Text)"
  try {
    $password = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "password.secret" -FolderPath $TestPath
    $apiKey = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "api-key.secret"   -FolderPath $TestPath
    $token = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "token.secret"    -FolderPath $TestPath

    Write-TestResult "Password retrieved correctly" ($password -eq "MyTestPassword123") "Length: $($password.Length)"
    Write-TestResult "API key retrieved correctly"  ($apiKey -eq "ApiKey456")         "Length: $($apiKey.Length)"
    Write-TestResult "Token retrieved correctly"    ($token -eq "Token789")          "Length: $($token.Length)"
  }
  catch {
    Write-TestResult "Secret retrieval" $false $_.Exception.Message
  }

  # TEST 6: Retrieve Secret as Credential
  Write-TestHeader "TEST 6: Retrieve Secret (PSCredential)"
  try {
    $cred = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "password.secret" -FolderPath $TestPath -AsCredential
    $isCredential = $cred -is [System.Management.Automation.PSCredential]
    $hasPassword = $cred.Password.Length -gt 0

    Write-TestResult "Returns PSCredential object" $isCredential "Type: $($cred.GetType().Name)"
    Write-TestResult "Credential has password"      $hasPassword
  }
  catch {
    Write-TestResult "Credential retrieval" $false $_.Exception.Message
  }

  # TEST 7: Create Certificate (PFX only)
  Write-TestHeader "TEST 7: Create Certificate (PFX Only)"
  try {
    New-SecureStoreCertificate -CertificateName "TestApp" -Password "CertPass123" -FolderPath $TestPath -ValidityYears 2 -Confirm:$false

    $pfxExists = Test-Path (Join-Path $TestPath "certs\TestApp.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\TestApp.pem")

    Write-TestResult "PFX certificate created" $pfxExists "certs\TestApp.pfx"
    Write-TestResult "PEM not created (as expected)" (-not $pemExists)
  }
  catch {
    Write-TestResult "Certificate creation (PFX)" $false $_.Exception.Message
  }

  # TEST 8: Create Certificate with PEM Export (RSA)
  Write-TestHeader "TEST 8: Create Certificate (PFX + PEM - RSA)"
  try {
    New-SecureStoreCertificate -CertificateName "WebServer" -Password "WebPass123" -FolderPath $TestPath -ExportPem -Confirm:$false 3>$null

    $pfxExists = Test-Path (Join-Path $TestPath "certs\WebServer.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\WebServer.pem")

    Write-TestResult "PFX certificate created" $pfxExists "certs\WebServer.pfx"
    Write-TestResult "PEM certificate created" $pemExists "certs\WebServer.pem"

    if ($pemExists) {
      $pemContent = Get-Content (Join-Path $TestPath "certs\WebServer.pem") -Raw
      $hasCertHeader = $pemContent -match "-----BEGIN CERTIFICATE-----"
      $hasCertFooter = $pemContent -match "-----END CERTIFICATE-----"
      $hasKeyHeader = $pemContent -match "-----BEGIN RSA PRIVATE KEY-----"
      $hasKeyFooter = $pemContent -match "-----END RSA PRIVATE KEY-----"
      $hasBase64 = $pemContent -match "[A-Za-z0-9+/=]+"

      # Verify Base64 is properly line-wrapped
      $lines = ($pemContent -split "`n" | Where-Object { $_ -match "^[A-Za-z0-9+/=]+$" })
      $hasLineBreaks = $lines.Count -gt 1
      $maxLineLength = if ($lines.Count -gt 0) { ($lines | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum } else { 0 }
      $properlyFormatted = $maxLineLength -le 76

      Write-TestResult "PEM has certificate header" $hasCertHeader
      Write-TestResult "PEM has certificate footer" $hasCertFooter

      if ($isPowerShell7) {
        Write-TestResult "PEM has RSA private key header (PS7+)" $hasKeyHeader
        Write-TestResult "PEM has RSA private key footer (PS7+)" $hasKeyFooter
      }
      else {
        Write-Host "[INFO] PowerShell 5.1 exports certificate-only PEM (no private key)" -ForegroundColor Yellow
        Write-TestResult "PEM certificate-only mode (PS5.1)" (-not $hasKeyHeader)
      }

      Write-TestResult "PEM contains Base64 data"    $hasBase64
      Write-TestResult "PEM has line breaks in Base64" $hasLineBreaks "Lines: $($lines.Count)"
      Write-TestResult "PEM lines properly formatted" $properlyFormatted "Max length: $maxLineLength"
    }
  }
  catch {
    Write-TestResult "Certificate creation (PEM - RSA)" $false $_.Exception.Message
  }

  # TEST 9: Create ECDSA Certificate with PEM Export
  Write-TestHeader "TEST 9: Create Certificate (PFX + PEM - ECDSA)"
  try {
    New-SecureStoreCertificate -CertificateName "EcdsaCert" -Password "EcdsaPass123" -FolderPath $TestPath -Algorithm ECDSA -CurveName nistP256 -ExportPem -Confirm:$false 3>$null

    $pfxExists = Test-Path (Join-Path $TestPath "certs\EcdsaCert.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\EcdsaCert.pem")

    Write-TestResult "ECDSA PFX certificate created" $pfxExists "certs\EcdsaCert.pfx"
    Write-TestResult "ECDSA PEM certificate created" $pemExists "certs\EcdsaCert.pem"

    if ($pemExists) {
      $pemContent = Get-Content (Join-Path $TestPath "certs\EcdsaCert.pem") -Raw
      $hasCertHeader = $pemContent -match "-----BEGIN CERTIFICATE-----"
      $hasCertFooter = $pemContent -match "-----END CERTIFICATE-----"
      $hasKeyHeader = $pemContent -match "-----BEGIN EC PRIVATE KEY-----"
      $hasKeyFooter = $pemContent -match "-----END EC PRIVATE KEY-----"

      Write-TestResult "PEM has certificate header" $hasCertHeader
      Write-TestResult "PEM has certificate footer" $hasCertFooter

      if ($isPowerShell7) {
        Write-TestResult "PEM has EC private key header (PS7+)" $hasKeyHeader
        Write-TestResult "PEM has EC private key footer (PS7+)" $hasKeyFooter
      }
      else {
        Write-Host "[INFO] PowerShell 5.1 exports certificate-only PEM (no private key)" -ForegroundColor Yellow
        Write-TestResult "PEM certificate-only mode (PS5.1)" (-not $hasKeyHeader)
      }
    }
  }
  catch {
    Write-TestResult "Certificate creation (PEM - ECDSA)" $false $_.Exception.Message
  }

  # TEST 10: Create Certificate with Custom Parameters
  Write-TestHeader "TEST 10: Certificate with Custom Parameters"
  try {
    New-SecureStoreCertificate -CertificateName "CustomCert" -Password "Custom123" -FolderPath $TestPath `
      -Subject "CN=custom.local, O=TestOrg" -ValidityYears 5 -ExportPem `
      -DnsName "custom.local", "www.custom.local" -Algorithm RSA -KeyLength 4096 -Confirm:$false 3>$null

    $pfxExists = Test-Path (Join-Path $TestPath "certs\CustomCert.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\CustomCert.pem")

    Write-TestResult "Custom certificate PFX created" $pfxExists
    Write-TestResult "Custom certificate PEM created" $pemExists
  }
  catch {
    Write-TestResult "Custom certificate creation" $false $_.Exception.Message
  }

  # TEST 11: Create Certificate in Store Only
  Write-TestHeader "TEST 11: Certificate Store Only Mode"
  try {
    $result = New-SecureStoreCertificate -CertificateName "StoreOnlyCert" -Password "StorePass123" -StoreOnly -Confirm:$false

    $certExists = Test-Path "Cert:\CurrentUser\My\$($result.Thumbprint)"
    $noPfx = -not (Test-Path (Join-Path $TestPath "certs\StoreOnlyCert.pfx"))

    Write-TestResult "Certificate created in store"      $certExists "Thumbprint: $($result.Thumbprint)"
    Write-TestResult "No PFX file created (as expected)" $noPfx
    Write-TestResult "StoreLocation property set"        ($null -ne $result.StoreLocation)

    # Cleanup
    if ($certExists) {
      Remove-Item "Cert:\CurrentUser\My\$($result.Thumbprint)" -Force
    }
  }
  catch {
    Write-TestResult "Certificate store only mode" $false $_.Exception.Message
  }

  # TEST 12: Inventory Listing (before cert-based secrets)
  Write-TestHeader "TEST 12: Inventory Listing"
  try {
    Write-Host "`nCalling Get-SecureStoreList:" -ForegroundColor Yellow
    Get-SecureStoreList -FolderPath $TestPath

    $keyFiles = Get-ChildItem (Join-Path $TestPath "bin")    -Filter "*.bin"
    $secretFiles = Get-ChildItem (Join-Path $TestPath "secrets")
    $certFiles = Get-ChildItem (Join-Path $TestPath "certs")

    # At this point only 7 certificate files exist:
    # TestApp.pfx, WebServer.pfx/pem, EcdsaCert.pfx/pem, CustomCert.pfx/pem
    Write-TestResult "Correct key count"    ($keyFiles.Count -eq 1) "Expected: 1, Actual: $($keyFiles.Count)"
    Write-TestResult "Correct secret count" ($secretFiles.Count -eq 3) "Expected: 3, Actual: $($secretFiles.Count)"
    Write-TestResult "Correct certificate count" ($certFiles.Count -eq 7) "Expected: 7, Actual: $($certFiles.Count)"
  }
  catch {
    Write-TestResult "Inventory listing" $false $_.Exception.Message
  }

  # TEST 13: Direct Path Access
  Write-TestHeader "TEST 13: Direct Path Access"
  try {
    $keyPath = Join-Path $TestPath "bin\TestApp.bin"
    $secretPath = Join-Path $TestPath "secrets\password.secret"
    $password = Get-SecureStoreSecret -KeyPath $keyPath -SecretPath $secretPath

    Write-TestResult "Direct path retrieval works" ($password -eq "MyTestPassword123")
  }
  catch {
    Write-TestResult "Direct path access" $false $_.Exception.Message
  }

  # TEST 14: Error Handling - Missing Key
  Write-TestHeader "TEST 14: Error Handling"
  try {
    $errorCaught = $false
    try {
      Get-SecureStoreSecret -KeyName "NonExistent" -SecretFileName "fake.secret" -FolderPath $TestPath -ErrorAction Stop
    }
    catch {
      $errorCaught = $true
    }
    Write-TestResult "Handles missing key file" $errorCaught
  }
  catch {
    Write-TestResult "Error handling" $false $_.Exception.Message
  }

  # TEST 15: Error Handling - Missing Secret
  try {
    $errorCaught = $false
    try {
      Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "missing.secret" -FolderPath $TestPath -ErrorAction Stop
    }
    catch {
      $errorCaught = $true
    }
    Write-TestResult "Handles missing secret file" $errorCaught
  }
  catch {
    Write-TestResult "Error handling (missing secret)" $false $_.Exception.Message
  }

  # TEST 16: Verify PFX Can Be Imported
  Write-TestHeader "TEST 16: Verify Certificates Are Valid"
  try {
    $pfxPath = Join-Path $TestPath "certs\WebServer.pfx"
    $certPassword = ConvertTo-SecureString "WebPass123" -AsPlainText -Force
    $pfxCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxPath, $certPassword)

    $hasPrivateKey = $pfxCert.HasPrivateKey
    $validDate = (Get-Date) -lt $pfxCert.NotAfter

    Write-TestResult "PFX has private key"            $hasPrivateKey
    Write-TestResult "Certificate is not expired"      $validDate "Expires: $($pfxCert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-TestResult "Certificate has thumbprint"      ($pfxCert.Thumbprint.Length -gt 0) "Thumbprint: $($pfxCert.Thumbprint)"

    $pfxCert.Dispose()
  }
  catch {
    Write-TestResult "Certificate validation" $false $_.Exception.Message
  }

  # TEST 17: Verify PEM Format
  Write-TestHeader "TEST 17: Verify PEM Format"
  try {
    $pemPath = Join-Path $TestPath "certs\WebServer.pem"
    $pemContent = Get-Content $pemPath -Raw

    # Extract certificate section
    $certMatch = [regex]::Match($pemContent, "-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $hasCert = $certMatch.Success

    Write-TestResult "PEM contains certificate" $hasCert

    if ($hasCert) {
      # Try to parse the certificate portion
      $certBase64 = $certMatch.Groups[1].Value -replace '\s', ''
      $certBytes = [Convert]::FromBase64String($certBase64)
      $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

      Write-TestResult "PEM certificate is parseable" ($null -ne $cert) "Subject: $($cert.Subject)"

      if ($isPowerShell7) {
        $keyMatch = [regex]::Match($pemContent, "-----BEGIN RSA PRIVATE KEY-----(.+?)-----END RSA PRIVATE KEY-----", [System.Text.RegularExpressions.RegexOptions]::Singleline)
        Write-TestResult "PEM contains private key (PS7+)" $keyMatch.Success
      }

      $cert.Dispose()
    }
  }
  catch {
    Write-TestResult "PEM validation" $false $_.Exception.Message
  }

  # =======================
  # CERTIFICATE-BASED SECRET ENCRYPTION TESTS
  # These tests validate the new Certificate encryption functionality.
  # =======================

  # TEST 18: Create Certificate-Encrypted Secret (Store)
  Write-TestHeader "TEST 18: Certificate-Encrypted Secret (Store)"
  try {
    # First, create a certificate in the store for encryption
    $certResult = New-SecureStoreCertificate -CertificateName "SecretEncryption" -Password "CertPass123" -StoreOnly -Confirm:$false

    $certExists = Test-Path "Cert:\CurrentUser\My\$($certResult.Thumbprint)"
    Write-TestResult "Encryption certificate created in store" $certExists "Thumbprint: $($certResult.Thumbprint)"

    # Encrypt a secret with the certificate
    New-SecureStoreSecret -SecretFileName "cert-secret-store.secret" -Password "MySecretValue123" -FolderPath $TestPath -CertificateThumbprint $certResult.Thumbprint

    $secretExists = Test-Path (Join-Path $TestPath "secrets\cert-secret-store.secret")
    Write-TestResult "Certificate-encrypted secret created" $secretExists "secrets\cert-secret-store.secret"

    # Verify the secret file contains version 3 format
    if ($secretExists) {
      $secretContent = Get-Content (Join-Path $TestPath "secrets\cert-secret-store.secret") -Raw | ConvertFrom-Json
      $isVersion3 = $secretContent.Version -eq 3
      $isCertMethod = $secretContent.EncryptionMethod -eq 'Certificate'
      $hasThumbprint = $secretContent.CertificateInfo.Thumbprint -eq $certResult.Thumbprint

      Write-TestResult "Secret uses version 3 format"       $isVersion3
      Write-TestResult "Secret uses Certificate encryption"  $isCertMethod
      Write-TestResult "Secret references correct certificate" $hasThumbprint
    }
  }
  catch {
    Write-TestResult "Certificate-encrypted secret (store)" $false $_.Exception.Message
  }

  # TEST 19: Retrieve Certificate-Encrypted Secret (Store)
  Write-TestHeader "TEST 19: Retrieve Certificate-Encrypted Secret (Store)"
  try {
    $retrievedSecret = Get-SecureStoreSecret -SecretFileName "cert-secret-store.secret" -FolderPath $TestPath -CertificateThumbprint $certResult.Thumbprint

    $correctValue = $retrievedSecret -eq "MySecretValue123"
    Write-TestResult "Certificate-encrypted secret retrieved correctly" $correctValue "Value matches: $correctValue"

    # Test retrieval as credential
    $cred = Get-SecureStoreSecret -SecretFileName "cert-secret-store.secret" -FolderPath $TestPath -CertificateThumbprint $certResult.Thumbprint -AsCredential -UserName "testuser"
    $isCredential = $cred -is [System.Management.Automation.PSCredential]
    $correctUsername = $cred.UserName -eq "testuser"

    Write-TestResult "Retrieved as PSCredential"     $isCredential
    Write-TestResult "Credential has correct username" $correctUsername

    # Cleanup certificate from store
    if (Test-Path "Cert:\CurrentUser\My\$($certResult.Thumbprint)") {
      Remove-Item "Cert:\CurrentUser\My\$($certResult.Thumbprint)" -Force
    }
  }
  catch {
    Write-TestResult "Retrieve certificate-encrypted secret (store)" $false $_.Exception.Message
  }

  # TEST 20: Create Certificate-Encrypted Secret (PFX File)
  Write-TestHeader "TEST 20: Certificate-Encrypted Secret (PFX File)"
  try {
    # Create a certificate and export to PFX
    New-SecureStoreCertificate -CertificateName "FileEncryption" -Password "FileCertPass123" -FolderPath $TestPath -Confirm:$false 3>$null

    $pfxPath = Join-Path $TestPath "certs\FileEncryption.pfx"
    $pfxExists = Test-Path $pfxPath
    Write-TestResult "PFX certificate created" $pfxExists "certs\FileEncryption.pfx"

    # Encrypt a secret with the PFX file
    New-SecureStoreSecret -SecretFileName "cert-secret-file.secret" -Password "FileSecretValue456" -FolderPath $TestPath -CertificatePath $pfxPath -CertificatePassword "FileCertPass123"

    $secretExists = Test-Path (Join-Path $TestPath "secrets\cert-secret-file.secret")
    Write-TestResult "Certificate-encrypted secret created (file)" $secretExists "secrets\cert-secret-file.secret"
  }
  catch {
    Write-TestResult "Certificate-encrypted secret (PFX file)" $false $_.Exception.Message
  }

  # TEST 21: Retrieve Certificate-Encrypted Secret (PFX File)
  Write-TestHeader "TEST 21: Retrieve Certificate-Encrypted Secret (PFX File)"
  try {
    $pfxPath = Join-Path $TestPath "certs\FileEncryption.pfx"
    $retrievedSecret = Get-SecureStoreSecret -SecretFileName "cert-secret-file.secret" -FolderPath $TestPath -CertificatePath $pfxPath -CertificatePassword "FileCertPass123"

    $correctValue = $retrievedSecret -eq "FileSecretValue456"
    Write-TestResult "Certificate-encrypted secret retrieved correctly (file)" $correctValue "Value matches: $correctValue"
  }
  catch {
    Write-TestResult "Retrieve certificate-encrypted secret (PFX file)" $false $_.Exception.Message
  }

  # TEST 22: ECDSA Certificate Rejection for Encryption
  Write-TestHeader "TEST 22: ECDSA Certificate Rejection"
  try {
    # Create an ECDSA certificate
    $ecdsaResult = New-SecureStoreCertificate -CertificateName "EcdsaTest" -Password "EcdsaPass123" -Algorithm ECDSA -StoreOnly -Confirm:$false

    $errorCaught = $false
    $errorMessage = ""
    try {
      # Try to encrypt with ECDSA certificate (should fail)
      New-SecureStoreSecret -SecretFileName "ecdsa-fail.secret" -Password "test" -FolderPath $TestPath -CertificateThumbprint $ecdsaResult.Thumbprint -ErrorAction Stop
    }
    catch {
      $errorCaught = $true
      $errorMessage = $_.Exception.Message
    }

    Write-TestResult "ECDSA certificate rejected for encryption" $errorCaught "Error caught: $errorCaught"

    if ($errorCaught) {
      $correctError = $errorMessage -like "*RSA*" -or $errorMessage -like "*encrypt*"
      Write-TestResult "Error message mentions RSA/encryption requirement" $correctError
    }

    # Cleanup ECDSA certificate
    if (Test-Path "Cert:\CurrentUser\My\$($ecdsaResult.Thumbprint)") {
      Remove-Item "Cert:\CurrentUser\My\$($ecdsaResult.Thumbprint)" -Force
    }
  }
  catch {
    Write-TestResult "ECDSA certificate rejection test" $false $_.Exception.Message
  }

  # TEST 23: Auto-Detection of Certificate from Payload
  Write-TestHeader "TEST 23: Auto-Detection of Certificate"
  try {
    # Create a new certificate
    $autoResult = New-SecureStoreCertificate -CertificateName "AutoDetect" -Password "AutoPass123" -StoreOnly -Confirm:$false

    # Encrypt secret with this certificate
    New-SecureStoreSecret -SecretFileName "auto-detect.secret" -Password "AutoValue789" -FolderPath $TestPath -CertificateThumbprint $autoResult.Thumbprint

    # Retrieve WITHOUT specifying certificate (should auto-detect from payload)
    $retrievedSecret = Get-SecureStoreSecret -SecretFileName "auto-detect.secret" -FolderPath $TestPath

    $correctValue = $retrievedSecret -eq "AutoValue789"
    Write-TestResult "Auto-detected certificate and decrypted correctly" $correctValue "Value matches: $correctValue"

    # Cleanup
    if (Test-Path "Cert:\CurrentUser\My\$($autoResult.Thumbprint)") {
      Remove-Item "Cert:\CurrentUser\My\$($autoResult.Thumbprint)" -Force
    }
  }
  catch {
    Write-TestResult "Auto-detection of certificate" $false $_.Exception.Message
  }

  # TEST 24: Version 2 and Version 3 Coexistence
  Write-TestHeader "TEST 24: Version 2 and Version 3 Coexistence"
  try {
    # Create a version 2 secret (AES)
    New-SecureStoreSecret -KeyName "CoexistKey" -SecretFileName "v2-secret.secret" -Password "Version2Value" -FolderPath $TestPath

    # Create a version 3 secret (Certificate)
    $coexistCert = New-SecureStoreCertificate -CertificateName "CoexistCert" -Password "CoexistPass" -StoreOnly -Confirm:$false
    New-SecureStoreSecret -SecretFileName "v3-secret.secret" -Password "Version3Value" -FolderPath $TestPath -CertificateThumbprint $coexistCert.Thumbprint

    # Retrieve both
    $v2Secret = Get-SecureStoreSecret -KeyName "CoexistKey" -SecretFileName "v2-secret.secret" -FolderPath $TestPath
    $v3Secret = Get-SecureStoreSecret -SecretFileName "v3-secret.secret" -FolderPath $TestPath -CertificateThumbprint $coexistCert.Thumbprint

    $v2Correct = $v2Secret -eq "Version2Value"
    $v3Correct = $v3Secret -eq "Version3Value"

    Write-TestResult "Version 2 (AES) secret works"       $v2Correct
    Write-TestResult "Version 3 (Certificate) secret works" $v3Correct
    Write-TestResult "Both versions coexist successfully"   ($v2Correct -and $v3Correct)

    # Cleanup
    if (Test-Path "Cert:\CurrentUser\My\$($coexistCert.Thumbprint)") {
      Remove-Item "Cert:\CurrentUser\My\$($coexistCert.Thumbprint)" -Force
    }
  }
  catch {
    Write-TestResult "Version 2 and Version 3 coexistence" $false $_.Exception.Message
  }

  # TEST 25: Wrong Certificate Error Handling
  Write-TestHeader "TEST 25: Wrong Certificate Error Handling"
  try {
    # Create two certificates
    $cert1 = New-SecureStoreCertificate -CertificateName "WrongCert1" -Password "Pass1" -StoreOnly -Confirm:$false
    $cert2 = New-SecureStoreCertificate -CertificateName "WrongCert2" -Password "Pass2" -StoreOnly -Confirm:$false

    # Encrypt with cert1
    New-SecureStoreSecret -SecretFileName "wrong-cert.secret" -Password "TestValue" -FolderPath $TestPath -CertificateThumbprint $cert1.Thumbprint

    # Try to decrypt with cert2 (should fail)
    $errorCaught = $false
    try {
      Get-SecureStoreSecret -SecretFileName "wrong-cert.secret" -FolderPath $TestPath -CertificateThumbprint $cert2.Thumbprint -ErrorAction Stop
    }
    catch {
      $errorCaught = $true
    }

    Write-TestResult "Decryption with wrong certificate fails" $errorCaught

    # Cleanup
    if (Test-Path "Cert:\CurrentUser\My\$($cert1.Thumbprint)") {
      Remove-Item "Cert:\CurrentUser\My\$($cert1.Thumbprint)" -Force
    }
    if (Test-Path "Cert:\CurrentUser\My\$($cert2.Thumbprint)") {
      Remove-Item "Cert:\CurrentUser\My\$($cert2.Thumbprint)" -Force
    }
  }
  catch {
    Write-TestResult "Wrong certificate error handling" $false $_.Exception.Message
  }

  # TEST 26: Final Inventory Listing (after cert-based secrets)
  Write-TestHeader "TEST 26: Final Inventory Listing"
  try {
    $finalCertFiles = Get-ChildItem (Join-Path $TestPath "certs")
    # After TEST 20, FileEncryption.pfx adds one more certificate, so we expect 8 files in total.
    Write-TestResult "Correct final certificate count" ($finalCertFiles.Count -eq 8) "Expected: 8, Actual: $($finalCertFiles.Count)"
  }
  catch {
    Write-TestResult "Final inventory listing" $false $_.Exception.Message
  }

  # Final Summary
  Write-TestSummary

}
catch {
  Write-Host "`nFATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host $_.ScriptStackTrace -ForegroundColor Gray
}
finally {
  # Cleanup prompt
  Write-Host "`n========================================" -ForegroundColor Yellow
  Write-Host "Test environment location: $TestPath" -ForegroundColor Cyan
  $cleanup = Read-Host "Delete entire test environment directory? (Y/N)"
  if ($cleanup -match '^[Yy]') {
    Remove-Item -Path $TestPath -Recurse -Force
    Write-Host "Test environment deleted: $TestPath" -ForegroundColor Green
  }
  else {
    Write-Host "Test environment preserved at: $TestPath" -ForegroundColor Cyan
  }
}
