using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace app.Certificates
{
    public class CertificateOperations
    {
        public const int KeySizeInBits = 4096;
        public const int SerialNumberSizeInBytes = 20;

        /// <summary>
        /// Get the info string for the target certificate.
        /// </summary>
        /// <param name="cert"></param>
        /// <returns>info</returns>
        public static string GetCertInfo(X509Certificate2 cert)
        {
            var info = $"subject: {cert.Subject}{Environment.NewLine}" +
                $"issuer: {cert.Issuer}{Environment.NewLine}" +
                $"serial #: {cert.SerialNumber}{Environment.NewLine}" +
                $"public key: {cert.GetPublicKeyString()}{Environment.NewLine}" +
                $"thumbprint: {cert.Thumbprint}{Environment.NewLine}" +
                $"hash: {cert.GetCertHashString()}{Environment.NewLine}" +
                $"expiration: {cert.GetExpirationDateString()}{Environment.NewLine}" +
                $"private key?: {cert.HasPrivateKey}{Environment.NewLine}";

            foreach (var extension in cert.Extensions)
            {
                info += $"{extension.Oid.FriendlyName}({extension.Oid.Value}){Environment.NewLine}";

                if (extension.Oid.FriendlyName == "Key Usage")
                {
                    var ext = (X509KeyUsageExtension)extension;
                    info += $"{ext.KeyUsages}{Environment.NewLine}";
                }

                if (extension.Oid.FriendlyName == "Basic Constraints")
                {
                    var ext = (X509BasicConstraintsExtension)extension;
                    info += $"{ext.CertificateAuthority}{Environment.NewLine}";
                    info += $"{ext.HasPathLengthConstraint}{Environment.NewLine}";
                    info += $"{ext.PathLengthConstraint}{Environment.NewLine}";
                }

                if (extension.Oid.FriendlyName == "Subject Key Identifier")
                {
                    var ext = (X509SubjectKeyIdentifierExtension)extension;
                    info += $"{ext.SubjectKeyIdentifier}{Environment.NewLine}";
                }

                if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                {
                    var ext = (X509EnhancedKeyUsageExtension)extension;
                    var oids = ext.EnhancedKeyUsages;
                    foreach (Oid oid in oids)
                    {
                        info += $"{oid.FriendlyName}({oid.Value}){Environment.NewLine}";
                    }
                }

                if (extension.Oid.FriendlyName == "Subject Alternative Name")
                {
                    var asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                    info += $"{asndata.Format(true)}{Environment.NewLine}";
                }
            }

            return info;
        }

        /// <summary>
        /// Create a self-signed certificate.
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="commonName"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 CreateSelfSignedCert(int keySize, string commonName,
            System.DateTimeOffset notBefore, System.DateTimeOffset notAfter)
        {
            using var rsa = RSA.Create(keySize);
            var request = new CertificateRequest(
                $"CN={commonName}",
                rsa,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                true/*certificateAuthority*/,
                false/*hasPathLengthConstraint*/,
                0/*pathLengthConstraint*/,
                true/*critical*/));

            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign/*keyUsages*/,
                false/*critical*/));

            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
                request.PublicKey/*subjectKeyIdentifier*/,
                false/*critical*/));

            var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
            subjectAlternativeNameBuilder.AddDnsName("test.com");
            subjectAlternativeNameBuilder.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

            return request.CreateSelfSigned(notBefore, notAfter);
        }

        /// <summary>
        /// Issue a signed certificate by the parent cert.
        /// </summary>
        /// <param name="parentCert"></param>
        /// <param name="keySize"></param>
        /// <param name="commonName"></param>
        /// <param name="flags"></param>
        /// <param name="oidCollection"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="includePrivateKey"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 IssueSignedCert(X509Certificate2 parentCert, int keySize, string commonName,
            X509KeyUsageFlags flags, OidCollection oidCollection,
            System.DateTimeOffset notBefore, System.DateTimeOffset notAfter,
            bool includePrivateKey)
        {
            using var rsa = RSA.Create(keySize);
            var request = new CertificateRequest(
                $"CN={commonName}",
                rsa,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                false/*certificateAuthority*/,
                false/*hasPathLengthConstraint*/,
                0/*pathLengthConstraint*/,
                false/*critical*/));

            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                flags/*keyUsages*/,
                false/*critical*/));

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                oidCollection/*oidCollection*/,
                true/*critical*/));

            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(
                request.PublicKey/*subjectKeyIdentifier*/,
                false/*critical*/));

            var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
            subjectAlternativeNameBuilder.AddDnsName("test.com");
            subjectAlternativeNameBuilder.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

            var serialNumber = new byte[SerialNumberSizeInBytes];
            RandomNumberGenerator.Fill(serialNumber);
            var cert = request.Create(parentCert, notBefore, notAfter, serialNumber);
            if (!includePrivateKey)
            {
                return cert;
            }

            var certWithPrivateKey = cert.CopyWithPrivateKey(rsa);
            cert.Dispose();
            return certWithPrivateKey;
        }

        /// <summary>
        /// Get a certificate with the target key storage flags based on the original cert.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="flags"></param>
        /// <returns>X509Certificate2</returns>
        public static X509Certificate2 GetCertWithStorageFlags(X509Certificate2 cert, X509KeyStorageFlags flags)
        {
            return new X509Certificate2(
                cert.Export(X509ContentType.Pkcs12),
                string.Empty, flags
            );
        }

        /// <summary>
        /// Validate the cert chain.
        /// If parentCert is not null, it will be added to the customer trusted store to be used in validation.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="parentCert"></param>
        /// <param name="revocationMode"></param>
        /// <param name="revocationFlag"></param>
        /// <returns>(valid or not, the chain status array)</returns>
        public static (bool, X509ChainStatus[]) ValidateCertificateChain(X509Certificate2 cert, X509Certificate2 parentCert,
            X509RevocationMode revocationMode, X509RevocationFlag revocationFlag)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = revocationMode;
            chain.ChainPolicy.RevocationFlag = revocationFlag;

            if (parentCert != null)
            {
                // If the parent cert is not trusted, we need to trust it manually.
                chain.ChainPolicy.ExtraStore.Add(parentCert);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Clear();
                chain.ChainPolicy.CustomTrustStore.Add(parentCert);
            }

            if (!chain.Build(cert))
            {
                return (false, chain.ChainStatus);
            }

            // Do further checking to make sure that there is matching thumbprint in the cert chain with our parent cert.
            var isValid = false;
            foreach (var element in chain.ChainElements)
            {
                if (element.Certificate.Thumbprint.Equals(parentCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    isValid = true;
                    break;
                }
            }

            return (isValid, chain.ChainStatus);
        }
    }
}