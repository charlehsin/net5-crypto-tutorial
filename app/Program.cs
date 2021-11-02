using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using app.Certificates;
using app.EncryptionDecryption;

namespace app
{
    class Program
    {
        static void Main(string[] args)
        {
            TryAesGcm();
            TryCreateCertificates();

            Console.Write($"{Environment.NewLine}Press any key to exit...");
            Console.ReadKey(true);
        }

        /// <summary>
        /// Try AES GCM operations.
        /// </summary>
        private static void TryAesGcm()
        {
            const string originalTest = "This is a test.";

            Console.Write($"{Environment.NewLine}Press any key to start AES GCM...");
            Console.ReadKey(true);
            Console.WriteLine($"{Environment.NewLine}");

            var aesGcmOperations = new AesGcmOperations();

            var key = aesGcmOperations.GenerateKey();

            var result = aesGcmOperations.Encrypt(key,
                Encoding.UTF8.GetBytes(originalTest));

            var nonce = result.Skip(0).Take(AesGcmOperations.NonceLength).ToArray();
            var tag = result.Skip(AesGcmOperations.NonceLength)
                .Take(AesGcmOperations.TagLength).ToArray();
            var cipher = result.Skip(AesGcmOperations.NonceLength + AesGcmOperations.TagLength).ToArray();
            var decrypted = aesGcmOperations.Decrypt(cipher, key, nonce, tag);

            Console.WriteLine($"original text: {originalTest}");
            Console.WriteLine($"key length: {key.Length}");
            Console.WriteLine($"nonce length: {nonce.Length}");
            Console.WriteLine($"tag length: {tag.Length}");
            Console.WriteLine($"cipher length: {cipher.Length}");
            Console.WriteLine($"decrypted text: {Encoding.UTF8.GetString(decrypted)}");

            Console.Write($"{Environment.NewLine}Press any key to finish AES GCM...");
            Console.ReadKey(true);
        }
    
        /// <summary>
        /// Try creating certificates.
        /// </summary>
        private static void TryCreateCertificates()
        {
            Console.Write($"{Environment.NewLine}Press any key to start creating certificates...");
            Console.ReadKey(true);
            Console.WriteLine($"{Environment.NewLine}");

            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            var certificateOperations = new CertificateOperations();
            using (var rootCert = certificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter))
            using (var cert = certificateOperations.IssueSignedCert(rootCert, CertificateOperations.KeySizeInBits, "A test TLS cert",
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1")/*id-kp-serverAuth*/ },
                notBefore, notAfter))
            {
                Console.WriteLine("Parent cert info:");
                Console.WriteLine($"{certificateOperations.GetCertInfo(rootCert)}");

                Console.Write($"{Environment.NewLine}Press any key to continue...");
                Console.ReadKey(true);
                Console.WriteLine($"{Environment.NewLine}");

                Console.WriteLine("Cert info:");
                Console.WriteLine($"{certificateOperations.GetCertInfo(cert)}");
            }
            Console.Write($"{Environment.NewLine}Press any key to finish creating certificates...");
            Console.ReadKey(true);
        }
    }
}
