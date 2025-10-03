<#
.SYNOPSIS
Comprehensive end-to-end test suite for SecureStore module.

.DESCRIPTION
Tests all SecureStore functions with visual output and validation.
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
        
    Write-TestResult "Base directory created" $basePath $TestPath
    Write-TestResult "Bin directory created" $binPath
    Write-TestResult "Secrets directory created" $secretPath
    Write-TestResult "Certs directory created" $certsPath
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
    Write-TestResult "Secret file created" $secretExists "secrets\password.secret"
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
    Write-TestResult "Third secret with same key created" $tokenExists
  }
  catch {
    Write-TestResult "Multiple secrets creation" $false $_.Exception.Message
  }

  # TEST 5: Retrieve Secrets as Plain Text
  Write-TestHeader "TEST 5: Retrieve Secrets (Plain Text)"
  try {
    $password = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "password.secret" -FolderPath $TestPath
    $apiKey = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "api-key.secret" -FolderPath $TestPath
    $token = Get-SecureStoreSecret -KeyName "TestApp" -SecretFileName "token.secret" -FolderPath $TestPath
        
    Write-TestResult "Password retrieved correctly" ($password -eq "MyTestPassword123") "Length: $($password.Length)"
    Write-TestResult "API key retrieved correctly" ($apiKey -eq "ApiKey456") "Length: $($apiKey.Length)"
    Write-TestResult "Token retrieved correctly" ($token -eq "Token789") "Length: $($token.Length)"
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
    Write-TestResult "Credential has password" $hasPassword
  }
  catch {
    Write-TestResult "Credential retrieval" $false $_.Exception.Message
  }

  # TEST 7: Create Certificate (PFX only)
  Write-TestHeader "TEST 7: Create Certificate (PFX Only)"
  try {
    New-SecureStoreCertificate -CertificateName "TestApp" -Password "CertPass123" -FolderPath $TestPath -ValidityYears 2
        
    $pfxExists = Test-Path (Join-Path $TestPath "certs\TestApp.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\TestApp.pem")
        
    Write-TestResult "PFX certificate created" $pfxExists "certs\TestApp.pfx"
    Write-TestResult "PEM not created (as expected)" (-not $pemExists)
  }
  catch {
    Write-TestResult "Certificate creation (PFX)" $false $_.Exception.Message
  }

  # TEST 8: Create Certificate with PEM Export
  Write-TestHeader "TEST 8: Create Certificate (PFX + PEM)"
  try {
    New-SecureStoreCertificate -CertificateName "WebServer" -Password "WebPass123" -FolderPath $TestPath -ExportPem
        
    $pfxExists = Test-Path (Join-Path $TestPath "certs\WebServer.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\WebServer.pem")
        
    Write-TestResult "PFX certificate created" $pfxExists "certs\WebServer.pfx"
    Write-TestResult "PEM certificate created" $pemExists "certs\WebServer.pem"
        
    if ($pemExists) {
      $pemContent = Get-Content (Join-Path $TestPath "certs\WebServer.pem") -Raw
      $hasPemHeader = $pemContent -match "-----BEGIN CERTIFICATE-----"
      $hasPemFooter = $pemContent -match "-----END CERTIFICATE-----"
      $hasBase64 = $pemContent -match "[A-Za-z0-9+/=]+"
            
      Write-TestResult "PEM has correct header" $hasPemHeader
      Write-TestResult "PEM has correct footer" $hasPemFooter
      Write-TestResult "PEM contains Base64 data" $hasBase64
    }
  }
  catch {
    Write-TestResult "Certificate creation (PEM)" $false $_.Exception.Message
  }

  # TEST 9: Create Certificate with Custom Parameters
  Write-TestHeader "TEST 9: Certificate with Custom Parameters"
  try {
    New-SecureStoreCertificate -CertificateName "CustomCert" -Password "Custom123" -FolderPath $TestPath `
      -Subject "CN=custom.local, O=TestOrg" -ValidityYears 5 -ExportPem `
      -DnsName "custom.local", "www.custom.local" -Algorithm RSA -KeyLength 4096
        
    $pfxExists = Test-Path (Join-Path $TestPath "certs\CustomCert.pfx")
    $pemExists = Test-Path (Join-Path $TestPath "certs\CustomCert.pem")
        
    Write-TestResult "Custom certificate PFX created" $pfxExists
    Write-TestResult "Custom certificate PEM created" $pemExists
  }
  catch {
    Write-TestResult "Custom certificate creation" $false $_.Exception.Message
  }

  # TEST 10: Inventory Listing
  Write-TestHeader "TEST 10: Inventory Listing"
  try {
    Write-Host "`nCalling Get-SecureStoreList:" -ForegroundColor Yellow
    Get-SecureStoreList -FolderPath $TestPath
        
    $keyFiles = Get-ChildItem (Join-Path $TestPath "bin") -Filter "*.bin"
    $secretFiles = Get-ChildItem (Join-Path $TestPath "secrets")
    $certFiles = Get-ChildItem (Join-Path $TestPath "certs")
        
    Write-TestResult "Correct key count" ($keyFiles.Count -eq 1) "Expected: 1, Actual: $($keyFiles.Count)"
    Write-TestResult "Correct secret count" ($secretFiles.Count -eq 3) "Expected: 3, Actual: $($secretFiles.Count)"
    Write-TestResult "Correct certificate count" ($certFiles.Count -eq 6) "Expected: 6, Actual: $($certFiles.Count)"
  }
  catch {
    Write-TestResult "Inventory listing" $false $_.Exception.Message
  }

  # TEST 11: Direct Path Access
  Write-TestHeader "TEST 11: Direct Path Access"
  try {
    $keyPath = Join-Path $TestPath "bin\TestApp.bin"
    $secretPath = Join-Path $TestPath "secrets\password.secret"
    $password = Get-SecureStoreSecret -KeyPath $keyPath -SecretPath $secretPath
        
    Write-TestResult "Direct path retrieval works" ($password -eq "MyTestPassword123")
  }
  catch {
    Write-TestResult "Direct path access" $false $_.Exception.Message
  }

  # TEST 12: Error Handling - Missing Key
  Write-TestHeader "TEST 12: Error Handling"
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

  # TEST 13: Error Handling - Missing Secret
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

  # TEST 14: Verify PFX Can Be Imported
  Write-TestHeader "TEST 14: Verify Certificates Are Valid"
  try {
    $pfxPath = Join-Path $TestPath "certs\WebServer.pfx"
    $certPassword = ConvertTo-SecureString "WebPass123" -AsPlainText -Force
    $pfxCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxPath, $certPassword)
        
    $hasPrivateKey = $pfxCert.HasPrivateKey
    $validDate = (Get-Date) -lt $pfxCert.NotAfter
        
    Write-TestResult "PFX has private key" $hasPrivateKey
    Write-TestResult "Certificate is not expired" $validDate "Expires: $($pfxCert.NotAfter.ToString('yyyy-MM-dd'))"
    Write-TestResult "Certificate has thumbprint" ($pfxCert.Thumbprint.Length -gt 0) "Thumbprint: $($pfxCert.Thumbprint)"
        
    $pfxCert.Dispose()
  }
  catch {
    Write-TestResult "Certificate validation" $false $_.Exception.Message
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