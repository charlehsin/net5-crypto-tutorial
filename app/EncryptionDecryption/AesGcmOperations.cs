using System.Linq;
using System.Security.Cryptography;

namespace app.EncryptionDecryption
{
    public class AesGcmOperations
    {
        public const int KeyLengthInBytes = 32;
        public readonly static int NonceLengthInBytes = AesGcm.NonceByteSizes.MaxSize;
        public readonly static int TagLengthInBytes = AesGcm.TagByteSizes.MaxSize;

        /// <summary>
        /// Generate the AES GCM key.
        /// </summary>
        /// <param name="keyLengthInBytes"></param>
        /// <returns>key</returns>
        public static byte[] GenerateKey(int keyLengthInBytes)
        {
            var key = new byte[keyLengthInBytes];
            RandomNumberGenerator.Fill(key);
            return key;
        }

        /// <summary>
        /// Encrypt the target.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="target"></param>
        /// <param name="nonceLengthInBytes"></param>
        /// <param name="tagLengthInBytes"></param>
        /// <returns>byte array with nonce, tag, cipher in order</returns>
        public static byte[] Encrypt(byte[] key, byte[] target,
            int nonceLengthInBytes, int tagLengthInBytes)
        {
            using var encryptor = new AesGcm(key);
            var cipher = new byte[target.Length];
            var tag = new byte[tagLengthInBytes];
            var nonce = GenerateNonce(nonceLengthInBytes);

            encryptor.Encrypt(nonce, target, cipher, tag);

            return nonce.Concat(tag).Concat(cipher).ToArray();
        }

        /// <summary>
        /// Decrypt the chiper.
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <param name="nonce"></param>
        /// <param name="tag"></param>
        /// <returns>decrypted result</returns>
        public static byte[] Decrypt(byte[] cipher, byte[] key,
            byte[] nonce, byte[] tag)
        {
            using var decryptor = new AesGcm(key);
            var plaintextBytes = new byte[cipher.Length];

            decryptor.Decrypt(nonce, cipher, tag, plaintextBytes);

            return plaintextBytes;
        }

        /// <summary>
        /// Generate the nonce.
        /// </summary>
        /// <param name="nonceLengthInBytes"></param>
        /// <returns>nonce</returns>
        private static byte[] GenerateNonce(int nonceLengthInBytes)
        {
            var nonce = new byte[nonceLengthInBytes];
            RandomNumberGenerator.Fill(nonce);
            return nonce;
        }
    }
}
