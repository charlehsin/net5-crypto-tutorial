using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using app.Certificates;

namespace app.TcpOperations
{
    public class TcpUtilities
    {
        /// <summary>
        /// Depending on to use TLS or not, return (NetworkStream object, null) or (null, SslStream object).
        /// </summary>
        /// <param name="tcpClient">The target TcpClient.</param>
        /// <param name="useTls">Use TLS or not.</param>
        /// <param name="userCertificateValidationCallback">A System.Net.Security.RemoteCertificateValidationCallback delegate.</param>
        /// <returns>The 1st is the NetworkStream object, and the 2nd is the SslStream object.</returns>
        public static (NetworkStream, SslStream) GetTargetStream(TcpClient tcpClient,
                                                                 bool useTls,
                                                                 RemoteCertificateValidationCallback userCertificateValidationCallback)
        {
            if (!useTls)
            {
                // Do not use TLS.
                return (tcpClient.GetStream(), null);
            }

            return (null, new SslStream(tcpClient.GetStream(), false,
                new RemoteCertificateValidationCallback(userCertificateValidationCallback)));
        }

        /// <summary>
        /// Check if the SSL stream is secure.
        /// </summary>
        /// <param name="sslStream">The target SSL stream.</param>
        /// <param name="useMutualAuth">Use mutual authentication or not.</param>
        /// <returns>True if the SSL stream is secure.</returns>
        public static bool CheckSslStream(SslStream sslStream,
                                          bool useMutualAuth)
        {
            if (sslStream == null)
            {
                // If we are not using SSL, return true.
                return true;
            }

            if (sslStream.IsAuthenticated && sslStream.IsEncrypted && sslStream.IsSigned)
            {
                if (!useMutualAuth)
                {
                    // If we do not need mutual authentication, return true here.
                    return true;
                }
                if (sslStream.IsMutuallyAuthenticated)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Verifies the remote Secure Sockets Layer (SSL) certificate used for authentication
        /// </summary>
        /// <param name="certificate">The certificate used to authenticate the remote party.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote certificate.</param>
        /// <param name="parentCert">The certificate used to sign the TLS certificate. If this is not null, this will be used to validate the cert chain.</param>
        /// <returns>True if the incoming certificate is accepted.</returns>
        public static bool ValidateCertificate(X509Certificate certificate,
                                               SslPolicyErrors sslPolicyErrors,
                                               X509Certificate2 parentCert)
        {
            if (parentCert == null)
            {
                // If the parent certificate is not provided, use the default .NET cert chain validation.
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }
                return false;
            }

            if (certificate == null || parentCert == null)
            {
                return false;
            }

            // The parent certificate is provided, we validate the cert chain ourselves.

            // TODO: Check certificate is revoked or not based on a CRL.

            (var isValid, var _) = CertificateOperations.ValidateCertificateChain(
                new X509Certificate2(certificate), parentCert, X509RevocationMode.NoCheck, X509RevocationFlag.EndCertificateOnly);

            return isValid;
        }
    }
}