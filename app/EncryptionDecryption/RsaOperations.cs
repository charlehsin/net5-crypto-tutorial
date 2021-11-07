using System.Security.Cryptography;

namespace app.EncryptionDecryption
{
    public class RsaOperations
    {
        /// <summary>
        /// Encrypt the target with public key.
        /// </summary>
        /// <param name="rsa">public key</param>
        /// <param name="target"></param>
        /// <returns>cipher byte array</returns>/
        public static byte[] Encrypt(RSA rsa, byte[] target)
        {
            return rsa.Encrypt(target, RSAEncryptionPadding.Pkcs1);
        }

        /// <summary>
        /// Decrypt the cipher with private key.
        /// </summary>
        /// <param name="rsa">private key</param>
        /// <param name="cipher"></param>
        /// <returns>decrypted result.</returns>/
        public static byte[] Decrypt(RSA rsa, byte[] cipher)
        {
            return rsa.Decrypt(cipher, RSAEncryptionPadding.Pkcs1);
        }
    }
}