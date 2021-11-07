# Tutorial for Crypto related topics

## Overview

This is a simple console app and you can choose the action you want to run.

This shows some tutorial codes for the following:
- Random number generation
- Symmetric AES GCM encryption and decryption
- Asymmetric RSA encryption and decryption
- Certificate operations
- Certificate store operations
- Signature

## GitHub Actions

- DOTNET build and test
- CodeQL

## NET CLI commands

- (in app folder) dotnet new console --framework net5.0
- dotnet run --project app\app.csproj

## Extra packages

- (For CmsSigner) dotnet add package System.Security.Cryptography.Pkcs --version 5.0.1

## References

### General

- https://docs.microsoft.com/en-us/dotnet/core/tutorials/with-visual-studio-code?pivots=dotnet-5-0
- https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model
- https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography
- https://www.strathweb.com/2019/04/roslyn-analyzers-in-code-fixes-in-omnisharp-and-vs-code/

### Encryption and decryption

- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=net-5.0
- https://www.scottbrady91.com/c-sharp/aes-gcm-dotnet
- https://docs.microsoft.com/en-us/dotnet/standard/security/encrypting-data 
- https://damienbod.com/2020/08/19/symmetric-and-asymmetric-encryption-in-net-core/ 

### Random number

- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-5.0

### Certificate operations

- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest?view=net-5.0
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509basicconstraintsextension?view=net-5.0
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509subjectkeyidentifierextension?view=net-5.0
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keyusageextension?view=net-5.0
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509enhancedkeyusageextension?view=net-5.0
- http://oid-info.com/get/1.3.6.1.5.5.7
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.subjectalternativenamebuilder?view=net-5.0
- https://stackoverflow.com/questions/48196350/generate-and-sign-certificate-request-using-pure-net-framework/48210587#48210587
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chain?view=net-5.0
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509chainpolicy?view=net-5.0 

### Certificate store operations

- https://stackoverflow.com/questions/66640533/how-to-provide-x509keystorageflags-to-certificaterequest 
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store.open?view=net-5.0

### Signature

- https://docs.microsoft.com/en-us/dotnet/standard/security/cryptographic-signatures
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms?view=windowsdesktop-5.0
- https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.cmssigner?view=windowsdesktop-5.0