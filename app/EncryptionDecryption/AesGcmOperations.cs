using System.Linq;
using System.Security.Cryptography;

namespace app.EncryptionDecryption
{    
    public class AesGcmOperations
    {
        public const int KeyLength = 32;
        public readonly static int NonceLength = AesGcm.NonceByteSizes.MaxSize;
        public readonly static int TagLength = AesGcm.TagByteSizes.MaxSize;

        /// <summary>
        /// Generate the AES GCM key.
        /// </summary>
        /// <returns>key</returns>
        public byte[] GenerateKey()
        {
            var key = new byte[KeyLength];
            RandomNumberGenerator.Fill(key);
            return key;
        }
        
        /// <summary>
        /// Encrypt the target.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="target"></param>
        /// <returns>byte array with nonce, tag, cipher in order</returns>
        public byte[] Encrypt(byte[] key, byte[] target)
        {
            using (var encryptor = new AesGcm(key))
            {
                var cipher = new byte[target.Length];
                var tag = new byte[TagLength];
                var nonce = GenerateNonce();

                encryptor.Encrypt(nonce, target, cipher, tag);

                return nonce.Concat(tag).Concat(cipher).ToArray();
            }
        }

        /// <summary>
        /// Decrypt the chiper.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        /// <param name="tag"></param>
        /// <returns>decrypted result</returns>
        public byte[] Decrypt(byte[] cipher, byte[] key,
            byte[] nonce, byte[] tag)
        {
            using (var decryptor = new AesGcm(key))
            {
                var plaintextBytes = new byte[cipher.Length];

                decryptor.Decrypt(nonce, cipher, tag, plaintextBytes);

                return plaintextBytes;
            }
        }

        /// <summary>
        /// Generate the nonce.
        /// </summary>
        /// <returns>nonce</returns>
        private byte[] GenerateNonce()
        {
            var nonce = new byte[NonceLength];
            RandomNumberGenerator.Fill(nonce);
            return nonce;
        }
    }
}
