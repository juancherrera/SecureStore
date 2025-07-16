SecureStore PowerShell Module v2.0
================================

INSTALLATION:
1. Extract all files to: C:\Program Files\WindowsPowerShell\Modules\SecureStore\
2. Import the module: Import-Module SecureStore
3. Test installation: Test-SecureStoreEnvironment

QUICK START:
New-SecureStoreSecret -KeyName "Test" -SecretFileName "test.secret" -Password "TestPass123"
Get-SecureStoreSecret -KeyName "Test" -SecretFileName "test.secret"
New-SecureStoreCertificate -CertificateName "TestCert" -Password "CertPass123"
Get-SecureStoreList

FOLDER STRUCTURE:
C:\SecureStore\
├── bin\                    # Encryption keys
├── secret\                 # Encrypted secrets
└── certs\                  # Certificates
