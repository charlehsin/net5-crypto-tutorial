# Tutorial and sample codes for .NET 5 Crypto related topics

## Overview

This is a simple console app and you can choose the action you want to run.

This shows sample codes for the following:
- General
   - https://docs.microsoft.com/en-us/dotnet/core/tutorials/with-visual-studio-code?pivots=dotnet-5-0
   - https://docs.microsoft.com/en-us/dotnet/standard/security/cryptography-model
   - https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography
- Random number generation
   - https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator?view=net-5.0
- Symmetric AES GCM encryption and decryption
   - https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm?view=net-5.0
   - https://www.scottbrady91.com/c-sharp/aes-gcm-dotnet
- Asymmetric RSA encryption and decryption
   - https://docs.microsoft.com/en-us/dotnet/standard/security/encrypting-data 
   - https://damienbod.com/2020/08/19/symmetric-and-asymmetric-encryption-in-net-core/ 
- Certificate operations
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
- Certificate store operations
   - https://stackoverflow.com/questions/66640533/how-to-provide-x509keystorageflags-to-certificaterequest 
   - https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store.open?view=net-5.0
- Signature
   - https://docs.microsoft.com/en-us/dotnet/standard/security/cryptographic-signatures
   - https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms?view=windowsdesktop-5.0
   - https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.cmssigner?view=windowsdesktop-5.0
- TCP operations
   - https://www.codeproject.com/Articles/5270779/High-Performance-TCP-Client-Server-using-TCPListen
   - https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcplistener?view=net-5.0
   - https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient?view=net-5.0
   - https://docs.microsoft.com/en-us/dotnet/api/system.net.security.sslstream?view=net-5.0
   - https://stackoverflow.com/questions/48198/how-can-you-find-out-which-process-is-listening-on-a-tcp-or-udp-port-on-windows

## Folder structure

- app\Certificates folder: This includes codes to
   - Create self-signed certificate.
   - Issue signed certificate.
   - Get certificate information.
   - Validate the certificate chain.
   - Get certificate object with the target storage flag.
- app\CertificateStore folder: This includes codes to
   - Find certificate from cert store by name or by thumbprint.
   - Add certificate into cert store.
   - Remove certificate from cert store.
- app\EncryptionDecryption folder: This includes codes to
   - Do symmetric AES GCM encryption and decryption.
   - Do asymmetric RSA encryption and descryption.
- app\Signature folder: This includes codes to
   - Sign the hash using RSA PKCS#1, and validate it.
   - Sign the message using CMS PKCS#7, and validate it.
- app\TcpOperations folder: This includes codes to
   - Create TCP listener with the choice to use TLS
   - Create TCP client with the choice to use TLS

## GitHub Actions included

- DOTNET build and test
- CodeQL

## Useful NET CLI commands

- (Create the default console app.)(Run in app folder.) dotnet new console --framework net5.0
- dotnet run --project app\app.csproj

## Extra packages

- (For CmsSigner) dotnet add package System.Security.Cryptography.Pkcs --version 5.0.1

## Userful references

- https://www.strathweb.com/2019/04/roslyn-analyzers-in-code-fixes-in-omnisharp-and-vs-code/



