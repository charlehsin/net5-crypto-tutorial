using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Logging.Debug;
using app.Certificates;
using app.CertificateStore;
using app.EncryptionDecryption;
using app.Signature;
using app.TcpOperations;

namespace app
{
    class Program
    {
        private static ILogger _logger;
        private static ILogger _loggerForMyTcpServer;
        private static ILogger _loggerForMyTcpClient;

        static void Main(string[] args)
        {
            if (args is null)
            {
                throw new ArgumentNullException(nameof(args));
            }

            SetupLogging();

            _logger.Log(LogLevel.Debug, "Console is started.");

            Console.Write("Enter 1 to try symmetric AES GCM encryption/decryption.");
            Console.Write($"{Environment.NewLine}Enter 2 to try asymmetric RSA encryption/decryption.");
            Console.Write($"{Environment.NewLine}Enter 3 to try creating certificates.");
            Console.Write($"{Environment.NewLine}Enter 4 to try cert store operations.");
            Console.Write($"{Environment.NewLine}Enter 5 to try RSA PKCS1 signature.");
            Console.Write($"{Environment.NewLine}Enter 6 to try CMS PKCS7 signature.");
            Console.Write($"{Environment.NewLine}Enter 7 to try starting a TCP server.");
            Console.Write($"{Environment.NewLine}Enter 8 to try starting a TCP client.");
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
                    case 5:
                        TryRsaPkcs1Signature();
                        break;
                    case 6:
                        TryCmsPkcs7Signature();
                        break;
                    case 7:
                        TryTcpServer();
                        break;
                    case 8:
                        TryTcpClient();
                        break;
                }
            }
        }

        /// <summary>
        /// Set up logging.
        /// </summary>
        private static void SetupLogging()
        {
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder
                    .AddFilter<DebugLoggerProvider>("app", LogLevel.Debug)
                    .AddFilter<ConsoleLoggerProvider>("app", LogLevel.Debug)
                    .AddDebug()
                    .AddConsole();
            });

            _logger = loggerFactory.CreateLogger<Program>();
            _loggerForMyTcpServer = loggerFactory.CreateLogger<MyTcpServer>();
            _loggerForMyTcpClient = loggerFactory.CreateLogger<MyTcpClient>();
        }

        /// <summary>
        /// Try AES GCM encryption/decryption.
        /// </summary>
        private static void TryAesGcm()
        {
            const string originalText = "This is a test.";

            var key = AesGcmOperations.GenerateKey(AesGcmOperations.KeyLengthInBytes);

            var result = AesGcmOperations.Encrypt(key,
                Encoding.UTF8.GetBytes(originalText),
                AesGcmOperations.NonceLengthInBytes, AesGcmOperations.TagLengthInBytes);

            var nonce = result.Skip(0).Take(AesGcmOperations.NonceLengthInBytes).ToArray();
            var tag = result.Skip(AesGcmOperations.NonceLengthInBytes)
                .Take(AesGcmOperations.TagLengthInBytes).ToArray();
            var cipher = result.Skip(AesGcmOperations.NonceLengthInBytes + AesGcmOperations.TagLengthInBytes).ToArray();
            var decrypted = AesGcmOperations.Decrypt(cipher, key, nonce, tag);

            Console.WriteLine($"original text: {originalText}");
            Console.WriteLine($"key length: {key.Length}");
            Console.WriteLine($"nonce length: {nonce.Length}");
            Console.WriteLine($"tag length: {tag.Length}");
            Console.WriteLine($"cipher length: {cipher.Length}");
            Console.WriteLine($"decrypted text: {Encoding.UTF8.GetString(decrypted)}");
        }

        /// <summary>
        /// Try RSA encryption/decryption.
        /// </summary>
        private static void TryRsa()
        {
            const string originalText = "This is a test.";

            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            using var rootCert = CertificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter);

            var rsaOperations = new RsaOperations();
            var cipher = RsaOperations.Encrypt(rootCert.GetRSAPublicKey(), Encoding.UTF8.GetBytes(originalText));
            var decrypted = RsaOperations.Decrypt(rootCert.GetRSAPrivateKey(), cipher);
            var decryptedText = Encoding.UTF8.GetString(decrypted);
            Console.WriteLine($"original text: {originalText}");
            Console.WriteLine($"decrypted text: {decryptedText}");
        }

        /// <summary>
        /// Try creating certificates.
        /// </summary>
        private static void TryCreateCertificates()
        {
            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            using var rootCert = CertificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter);
            using var cert = CertificateOperations.IssueSignedCert(rootCert, CertificateOperations.KeySizeInBits, "A test TLS cert",
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1")/*id-kp-serverAuth*/ },
                notBefore, notAfter, true);

            Console.WriteLine("Parent cert info:");
            Console.WriteLine($"{CertificateOperations.GetCertInfo(rootCert)}");

            Console.Write($"{Environment.NewLine}Press any key to continue...");
            Console.ReadKey(true);
            Console.WriteLine($"{Environment.NewLine}");

            Console.WriteLine("Cert info:");
            Console.WriteLine($"{CertificateOperations.GetCertInfo(cert)}");

            Console.WriteLine("Validate cert chain:");
            (var isValid, var chainStatusArray) = CertificateOperations.ValidateCertificateChain(cert, rootCert,
                X509RevocationMode.NoCheck, X509RevocationFlag.EndCertificateOnly);
            Console.Write($"{isValid} ");
            foreach (var status in chainStatusArray)
            {
                Console.Write($"{status.StatusInformation} ");
            }
            Console.WriteLine(string.Empty);
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

            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            using var rootCert = CertificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter);
            using var cert = CertificateOperations.IssueSignedCert(rootCert, CertificateOperations.KeySizeInBits, "A test TLS cert",
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1")/*id-kp-serverAuth*/ },
                notBefore, notAfter, true);
            using var newCert = CertificateOperations.GetCertWithStorageFlags(cert,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            var certStoreOperations = new CertificateStoreOperations();
            var targetCert = CertificateStoreOperations.FindNotExpiredCertFromCertStoreByName("CN=A test TLS cert",
                StoreLocation.LocalMachine, StoreName.My);
            Console.WriteLine($"{(targetCert == null ? cannotFindCert : foundCert)}");
            targetCert?.Dispose();
            targetCert = CertificateStoreOperations.FindNotExpiredCertFromCertStoreByThumbprint(newCert.Thumbprint,
                StoreLocation.LocalMachine, StoreName.My);
            Console.WriteLine($"{(targetCert == null ? cannotFindCertByThumbprint : foundCertByThumbprint)}");
            targetCert?.Dispose();

            Console.WriteLine($"Add the cert into cert store.");
            CertificateStoreOperations.AddCertificateIntoCertStore(newCert, StoreLocation.LocalMachine, StoreName.My);
            targetCert = CertificateStoreOperations.FindNotExpiredCertFromCertStoreByName("CN=A test TLS cert",
                StoreLocation.LocalMachine, StoreName.My);
            Console.WriteLine($"{(targetCert == null ? cannotFindCert : foundCert)}");
            targetCert?.Dispose();
            targetCert = CertificateStoreOperations.FindNotExpiredCertFromCertStoreByThumbprint(newCert.Thumbprint,
                StoreLocation.LocalMachine, StoreName.My);
            Console.WriteLine($"{(targetCert == null ? cannotFindCertByThumbprint : foundCertByThumbprint)}");
            targetCert?.Dispose();

            Console.WriteLine($"Remove the cert from cert store.");
            CertificateStoreOperations.RemoveCertificateFromCertStore(newCert, StoreLocation.LocalMachine, StoreName.My);
            targetCert = CertificateStoreOperations.FindNotExpiredCertFromCertStoreByName("CN=A test TLS cert",
                StoreLocation.LocalMachine, StoreName.My);
            Console.WriteLine($"{(targetCert == null ? cannotFindCert : foundCert)}");
            targetCert?.Dispose();
            targetCert = CertificateStoreOperations.FindNotExpiredCertFromCertStoreByThumbprint(newCert.Thumbprint,
                StoreLocation.LocalMachine, StoreName.My);
            Console.WriteLine($"{(targetCert == null ? cannotFindCertByThumbprint : foundCertByThumbprint)}");
            targetCert?.Dispose();
        }

        /// <summary>
        /// Try RSA PKCS1 signature.
        /// </summary>
        private static void TryRsaPkcs1Signature()
        {
            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            using var rootCert = CertificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter);

            var originalData = new byte[50];
            RandomNumberGenerator.Fill(originalData);

            var rsaPkcs1Signer = new RsaPkcs1Signer();

            var originalHash = RsaPkcs1Signer.GetSha512Hash(originalData);

            var signedHash = RsaPkcs1Signer.Sign(rootCert.GetRSAPrivateKey(),
                RsaPkcs1Signer.SHA512HashAlgorithm, originalHash);

            var isValid = RsaPkcs1Signer.Verify(rootCert.GetRSAPublicKey(), RsaPkcs1Signer.SHA512HashAlgorithm,
                originalHash, signedHash);
            Console.WriteLine($"Signed hash is not changed. Is the signature valid? {isValid}");

            signedHash[2] = 0x2;
            signedHash[3] = 0x2;
            isValid = RsaPkcs1Signer.Verify(rootCert.GetRSAPublicKey(), RsaPkcs1Signer.SHA512HashAlgorithm,
                originalHash, signedHash);
            Console.WriteLine($"Signed hash is changed. Is the signature valid? {isValid}");
        }

        /// <summary>
        /// Try CMS PKCS7 signature.
        /// </summary>
        private static void TryCmsPkcs7Signature()
        {
            var notBefore = DateTimeOffset.UtcNow.AddDays(-45);
            var notAfter = DateTimeOffset.UtcNow.AddDays(365);
            using var rootCert = CertificateOperations.CreateSelfSignedCert(CertificateOperations.KeySizeInBits, "A test root",
                notBefore, notAfter);

            var originalMessage = new byte[50];
            RandomNumberGenerator.Fill(originalMessage);

            var cmsPkcs7Signer = new CmsPkcs7Signer();
            var encodedMessage = CmsPkcs7Signer.Sign(rootCert, originalMessage);

            var isValid = CmsPkcs7Signer.Verify(encodedMessage, out _, out _);
            Console.WriteLine($"Encoded message is not changed. Is the signature valid? {isValid}");

            encodedMessage[2] = 0x2;
            encodedMessage[3] = 0x2;
            isValid = CmsPkcs7Signer.Verify(encodedMessage, out _, out _);
            Console.WriteLine($"Encoded message is changed. Is the signature valid? {isValid}");
        }

        /// <summary>
        /// Try TCP server operations.
        /// </summary>
        private static void TryTcpServer()
        {
            Console.Write($"{Environment.NewLine}Press any key to stop listening...");
            Console.WriteLine($"{Environment.NewLine}");

            var myTcpServer = new MyTcpServer(_loggerForMyTcpServer, hostIp: null, listeningPort: 5001,
                maxConcurrentClients: 5);

            // Run the main server loop in a different thread.
            var serverThread = new Thread(myTcpServer.Run);
            serverThread.Start();

            // Dummy task to try sending data to the 1st accepted client.
            Task.Run(async () =>
            {
                // Wait until we have at least 1 client connected.
                int clientCount;
                while ((clientCount = myTcpServer.GetAcceptedClients().Length) == 0)
                {
                    Thread.Sleep(1000);
                }

                var acceptedClients = myTcpServer.GetAcceptedClients();
                if (acceptedClients.Length == 0)
                {
                    return;
                }

                // For tutorial purpose, send dummy data to the 1st accepted client.
                try
                {
                    int i = 1;
                    while (true)
                    {
                        byte[] msg = Encoding.ASCII.GetBytes($"{i++}");
                        await myTcpServer.WriteToClientAsync(acceptedClients[0], msg, 0, msg.Length);
                        Thread.Sleep(1000);
                    }
                }
                catch (Exception e)
                {
                    _logger.Log(LogLevel.Trace, $"{e}");
                }
            });

            // Waiting for key event to stop.
            Console.ReadKey(true);

            // Signal the main server loop to finish.
            myTcpServer.Stop();
            // Wait fo the thread exit.
            serverThread.Join();
        }

        /// <summary>
        /// Try TCP client operations.
        /// </summary>
        private static void TryTcpClient()
        {
            Console.Write($"{Environment.NewLine}Press any key to stop connection...");
            Console.WriteLine($"{Environment.NewLine}");

            var myTcpClient = new MyTcpClient(_loggerForMyTcpClient, serverIp: "127.0.0.1", serverPort: 5001);

            // Run the main client loop in a different thread.
            var clientTask = Task.Run(async () =>
            {
                await myTcpClient.RunAsync().ConfigureAwait(false);
            });

            // Dummy task to try sending data to the server.
            Task.Run(async () =>
            {
                // Wait until the client is connected to the server.
                while (!myTcpClient.IsReadyToWrite)
                {
                    Thread.Sleep(1000);
                }

                // For tutorial purpose, send dummy data to the 1st accepted client.
                try
                {
                    int i = 1;
                    while (true)
                    {
                        byte[] msg = Encoding.ASCII.GetBytes($"{i++}");
                        await myTcpClient.WriteAsync(msg, 0, msg.Length);
                        Thread.Sleep(1000);
                    }
                }
                catch (Exception e)
                {
                    _logger.Log(LogLevel.Trace, $"{e}");
                }
            });

            // Waiting for key event to stop.
            Console.ReadKey(true);

            // Signal the main server loop to finish.
            myTcpClient.Stop();
            // Wait fo the thread exit.
            clientTask.Wait();
        }
    }
}
