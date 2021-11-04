using System.Security.Cryptography;

namespace app.EncryptionDecryption
{
    public class RsaOperations
    {
        /// <summary>
        /// Encrypt the target.
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="target"></param>
        /// <returns>cipher byte array</returns>/
        public byte[] Encrypt(RSA rsa, byte[] target)
        {            
            return rsa.Encrypt(target, RSAEncryptionPadding.Pkcs1);
        }
        
        /// <summary>
        /// Decrypt the cipher.
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="cipher"></param>
        /// <returns>decrypted result.</returns>/
        public byte[] Decrypt(RSA rsa, byte[] cipher)
        {
            return rsa.Decrypt(cipher, RSAEncryptionPadding.Pkcs1);
        }
    }
}