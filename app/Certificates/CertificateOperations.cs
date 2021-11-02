using System;
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
        public string GetCertInfo(X509Certificate2 cert)
        {
            var info = $"subject: {cert.Subject}{Environment.NewLine}" +
                $"issuer: {cert.Issuer}{Environment.NewLine}" +
                $"serial #: {cert.SerialNumber}{Environment.NewLine}" +
                $"public key: {cert.GetPublicKeyString()}{Environment.NewLine}" +
                $"thumbprint: {cert.Thumbprint}{Environment.NewLine}" +
                $"hash: {cert.GetCertHashString()}{Environment.NewLine}" +
                $"expiration: {cert.GetExpirationDateString()}{Environment.NewLine}";

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
        public X509Certificate2 CreateSelfSignedCert(int keySize, string commonName,
            System.DateTimeOffset notBefore, System.DateTimeOffset notAfter)
        {
            using (var rsa = RSA.Create(keySize))
            {
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

                return request.CreateSelfSigned(notBefore, notAfter);
            }
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
        /// <returns>X509Certificate2</returns>
        public X509Certificate2 IssueSignedCert(X509Certificate2 parentCert, int keySize, string commonName,
            X509KeyUsageFlags flags, OidCollection oidCollection,
            System.DateTimeOffset notBefore, System.DateTimeOffset notAfter)
        {
            using (var rsa = RSA.Create(keySize))
            {
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

                var serialNumber = new byte[SerialNumberSizeInBytes];
                RandomNumberGenerator.Fill(serialNumber);
                return request.Create(parentCert, notBefore, notAfter, serialNumber);
            }
        }
    }
}