using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using app.Certificates;
using app.CertificateStore;
using app.EncryptionDecryption;

namespace app
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter 1 to try symmetric AES GCM encryption/decryption.");
            Console.Write($"{Environment.NewLine}Enter 2 to try asymmetric RSA encryption/decryption.");
            Console.Write($"{Environment.NewLine}Enter 3 to try creating certificates.");
            Console.Write($"{Environment.NewLine}Enter 4 to try cert store operations.");
            Console.Write($"{Environment.NewLine}Enter an integer: ");

            var userInput = Console.ReadLine();
            if (int.TryParse(userInput, out var userInputNumber))
            {
                switch (userInputNumber)
                {
                    case 1:
                        TryAesGcm();
                        break;
                    case 2:
                        TryRsa();
                        break;
                    case 3:
                        TryCreateCertificates();
                        break;
                    case 4:
                        TryCertStoreOperations();
                        break;
                }
            }
        }

        /// <summary>
        /// Try AES GCM encryption/decryption.
        /// </summary>
        private static void TryAesGcm()
        {
            const string originalText = "This is a test.";

            Console.Write($"{Environment.NewLine}Press any key to start AES GCM...");
            Console.ReadKey(true);
            Console.WriteLine($"{Environment.NewLine}");

            var aesGcmOperations = new AesGcmOperations();

            var key = aesGcmOperations.GenerateKey(AesGcmOperations.KeyLengthInBytes);

            var result = aesGcmOperations.Encrypt(key,
                Encoding.UTF8.GetBytes(originalText),
                AesGcmOperations.NonceLengthInBytes, AesGcmOperations.TagLengthInBytes);

            var nonce = result.Skip(0).Take(AesGcmOperations.NonceLengthInBytes).ToArray();
            var tag = result.Skip(AesGcmOperations.NonceLengthInBytes)
                .Take(AesGcmOperations.TagLengthInBytes).ToArray();
            var cipher = result.Skip(AesGcmOperations.NonceLengthInBytes + AesGcmOperations.TagLengthInBytes).ToArray();
            var decrypted = aesGcmOperations.Decrypt(cipher, key, nonce, tag);

            Console.WriteLine($"original text: {originalText}");
            Console.WriteLine($"key length: {key.Length}");
            Console.WriteLine($"nonce length: {nonce.Length}");
            Console.WriteLine($"tag length: {tag.Length}");
            Console.WriteLine($"cipher length: {cipher.Length}");
            Console.WriteLine($"decrypted text: {Encoding.UTF8.GetString(decrypted)}");

            Console.Write($"{Environment.NewLine}Press any key to finish AES GCM...");
            Console.ReadKey(true);
        }

        /// <summary>
        /// Try RSA encryption/decryption.
        /// </summary>
        private static void TryRsa()
        {
            const string originalText = "This is a test.";
            var decryptedText = string.Empty;

            Console.Write($"{Environment.NewLine}Press any key to start RSA...");
            Console.ReadKey(true);
            Console.WriteLine($"{Environment.NewLine}");

            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            var certificateOperations = new CertificateOperations();
            using (var rootCert = certificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter))
            {
                var rsaOperations = new RsaOperations();
                var cipher = rsaOperations.Encrypt(rootCert.GetRSAPublicKey(), Encoding.UTF8.GetBytes(originalText));
                var decrypted = rsaOperations.Decrypt(rootCert.GetRSAPrivateKey(), cipher);
                decryptedText = Encoding.UTF8.GetString(decrypted);
            }        

            Console.WriteLine($"original text: {originalText}");
            Console.WriteLine($"decrypted text: {decryptedText}");
            
            Console.Write($"{Environment.NewLine}Press any key to finish RSA...");
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
                notBefore, notAfter, true))
            {
                Console.WriteLine("Parent cert info:");
                Console.WriteLine($"{certificateOperations.GetCertInfo(rootCert)}");

                Console.Write($"{Environment.NewLine}Press any key to continue...");
                Console.ReadKey(true);
                Console.WriteLine($"{Environment.NewLine}");

                Console.WriteLine("Cert info:");
                Console.WriteLine($"{certificateOperations.GetCertInfo(cert)}");

                Console.WriteLine("Validate cert chain:");
                (var isValid, var chainStatusArray) = certificateOperations.ValidateCertificateChain(cert, rootCert,
                    X509RevocationMode.NoCheck, X509RevocationFlag.EndCertificateOnly);
                Console.Write($"{isValid} ");
                foreach (var status in chainStatusArray)
                {
                    Console.Write($"{status.StatusInformation} ");
                }
                Console.WriteLine(string.Empty);
            }
            Console.Write($"{Environment.NewLine}Press any key to finish creating certificates...");
            Console.ReadKey(true);
        }

        /// <summary>
        /// Try cert store operations.
        /// </summary>
        private static void TryCertStoreOperations()
        {
            const string cannotFindCert = "Cannot find the cert.";
            const string foundCert = "Found the cert by name.";
            const string cannotFindCertByThumbprint = "Cannot find the cert by thumbprint.";
            const string foundCertByThumbprint = "Found the cert by thumbprint.";

            Console.Write($"{Environment.NewLine}Press any key to start cert store operations...");
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
                notBefore, notAfter, true))
            using (var newCert = certificateOperations.GetCertWithStorageFlags(cert,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable))
            {
                var certStoreOperations = new CertificateStoreOperations();
                var targetCert = certStoreOperations.FindNotExpiredCertFromCertStoreByName("CN=A test TLS cert",
                    StoreLocation.LocalMachine, StoreName.My);
                Console.WriteLine($"{(targetCert == null ? cannotFindCert : foundCert)}");
                targetCert?.Dispose();
                targetCert = certStoreOperations.FindNotExpiredCertFromCertStoreByThumbprint(newCert.Thumbprint,
                    StoreLocation.LocalMachine, StoreName.My);
                Console.WriteLine($"{(targetCert == null ? cannotFindCertByThumbprint : foundCertByThumbprint)}");
                targetCert?.Dispose();

                Console.WriteLine($"Add the cert into cert store.");
                certStoreOperations.AddCertificateIntoCertStore(newCert, StoreLocation.LocalMachine, StoreName.My);
                targetCert = certStoreOperations.FindNotExpiredCertFromCertStoreByName("CN=A test TLS cert",
                    StoreLocation.LocalMachine, StoreName.My);
                Console.WriteLine($"{(targetCert == null ? cannotFindCert : foundCert)}");
                targetCert?.Dispose();
                targetCert = certStoreOperations.FindNotExpiredCertFromCertStoreByThumbprint(newCert.Thumbprint,
                    StoreLocation.LocalMachine, StoreName.My);
                Console.WriteLine($"{(targetCert == null ? cannotFindCertByThumbprint : foundCertByThumbprint)}");
                targetCert?.Dispose();

                Console.WriteLine($"Remove the cert from cert store.");
                certStoreOperations.RemoveCertificateFromCertStore(newCert, StoreLocation.LocalMachine, StoreName.My);
                targetCert = certStoreOperations.FindNotExpiredCertFromCertStoreByName("CN=A test TLS cert",
                    StoreLocation.LocalMachine, StoreName.My);
                Console.WriteLine($"{(targetCert == null ? cannotFindCert : foundCert)}");
                targetCert?.Dispose();
                targetCert = certStoreOperations.FindNotExpiredCertFromCertStoreByThumbprint(newCert.Thumbprint,
                    StoreLocation.LocalMachine, StoreName.My);
                Console.WriteLine($"{(targetCert == null ? cannotFindCertByThumbprint : foundCertByThumbprint)}");
                targetCert?.Dispose();
            }
            Console.Write($"{Environment.NewLine}Press any key to finish cert store operations...");
            Console.ReadKey(true);
        }
    }
}
