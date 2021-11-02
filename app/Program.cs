using System;
using System.Linq;
using System.Text;
using app.EncryptionDecryption;

namespace app
{
    class Program
    {
        static void Main(string[] args)
        {
            TryAesGcm();

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
    }
}
