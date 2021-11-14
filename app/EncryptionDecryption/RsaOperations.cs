using System.Security.Cryptography;

namespace app.EncryptionDecryption
{
    public class RsaOperations
    {
        /// <summary>
        /// Encrypt the target with public key.
        /// </summary>
        /// <param name="rsa">The public key.</param>
        /// <param name="target">The data to be encrypted.</param>
        /// <returns>The cipher byte array.</returns>/
        public static byte[] Encrypt(RSA rsa, byte[] target)
        {
            return rsa.Encrypt(target, RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// Decrypt the cipher with private key.
        /// </summary>
        /// <param name="rsa">The private key.</param>
        /// <param name="cipher">The cipher to be decrypted.</param>
        /// <returns>The decrypted result.</returns>/
        public static byte[] Decrypt(RSA rsa, byte[] cipher)
        {
            return rsa.Decrypt(cipher, RSAEncryptionPadding.Pkcs1);
        }
    }
}