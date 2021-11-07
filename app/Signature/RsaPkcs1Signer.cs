using System.Security.Cryptography;

namespace app.Signature
{
    public class RsaPkcs1Signer
    {
        public const string SHA512HashAlgorithm = "SHA512";

        /// <summary>
        /// Get the SHA512 hash of the data.
        /// </summary>
        /// <param name="data"></param>
        /// <returns>hash</returns>
        public static byte[] GetSha512Hash(byte[] data)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
        }

        /// <summary>
        /// Sign the target hash with private key.
        /// The hash needs to match the hashAlg.
        /// </summary>
        /// <param name="rsa">private key</param>
        /// <param name="hashAlg"></param>
        /// <param name="hash"></param>
        /// <returns>signed hash</returns>
        public static byte[] Sign(RSA rsa, string hashAlg, byte[] hash)
        {
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm(hashAlg);
            return rsaFormatter.CreateSignature(hash);
        }

        /// <summary>
        /// Verify the signed hash with public key.
        /// </summary>
        /// <param name="rsa">public key</param>
        /// <param name="hashAlg"></param>
        /// <param name="hash"></param>
        /// <param name="signedHash"></param>
        /// <returns>True if it is valid.</returns>
        public static bool Verify(RSA rsa, string hashAlg, byte[] hash, byte[] signedHash)
        {
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm(hashAlg);
            return rsaDeformatter.VerifySignature(hash, signedHash);
        }
    }
}