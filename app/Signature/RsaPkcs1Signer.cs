using System.Security.Cryptography;

namespace app.Signature
{
    public class RsaPkcs1Signer
    {
        public const string SHA512HashAlgorithm = "SHA512";

        /// <summary>
        /// Get the SHA512 hash of the data.
        /// </summary>
        /// <param name="data">The target data to compute hash.</param>
        /// <returns>The SHA512 hash.</returns>
        public static byte[] GetSha512Hash(byte[] data)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
        }

        /// <summary>
        /// Sign the target hash with private key.
        /// The hash needs to match the hashAlg.
        /// </summary>
        /// <param name="rsa">The private key.</param>
        /// <param name="hashAlg">The name of the hash algorithm to use for creating the signature.</param>
        /// <param name="hash">The target hash.</param>
        /// <returns>The signature.</returns>
        public static byte[] Sign(RSA rsa, string hashAlg, byte[] hash)
        {
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm(hashAlg);
            return rsaFormatter.CreateSignature(hash);
        }

        /// <summary>
        /// Verify the signature with public key.
        /// </summary>
        /// <param name="rsa">The public key.</param>
        /// <param name="hashAlg">The name of the hash algorithm to use for verifying the signature.</param>
        /// <param name="hash">The data signed with signature.</param>
        /// <param name="signature">The signature to be verified for hash.</param>
        /// <returns>True if it is valid.</returns>
        public static bool Verify(RSA rsa, string hashAlg, byte[] hash, byte[] signature)
        {
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm(hashAlg);
            return rsaDeformatter.VerifySignature(hash, signature);
        }
    }
}