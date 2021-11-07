using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;

namespace app.Signature
{
    public class CmsPkcs7Signer
    {
        /// <summary>
        /// Sign the target message.
        /// </summary>
        /// <param name="signerCert"></param>
        /// <param name="message"></param>
        /// <returns>encoded message</returns>
        public static byte[] Sign(X509Certificate2 signerCert, byte[] message)
        {
            var contentInfo = new ContentInfo(message);
            var signedCms = new SignedCms(contentInfo);
            var cmsSigner = new CmsSigner(signerCert)
            {
                IncludeOption = X509IncludeOption.EndCertOnly
            };
            signedCms.ComputeSignature(cmsSigner, true);
            return signedCms.Encode();
        }

        /// <summary>
        /// Verify the encoded message.
        /// </summary>
        /// <param name="encodedMessage"></param>
        /// <param name="originalMessage">Return the original message if the return is true.</param>
        /// <param name="signerCert">Return the signer cert if the return is true.</param>
        /// <returns>True if this is valid.</returns>
        public static bool Verify(byte[] encodedMessage, out byte[] originalMessage,
            out X509Certificate2 signerCert)
        {
            var signedCms = new SignedCms();
            try
            {
                signedCms.Decode(encodedMessage);
                signedCms.CheckSignature(true);
            }
            catch (CryptographicException)
            {
                originalMessage = null;
                signerCert = null;
                return false;
            }
            originalMessage = signedCms.ContentInfo.Content;
            signerCert = signedCms.Certificates[0];
            return true;
        }
    }
}