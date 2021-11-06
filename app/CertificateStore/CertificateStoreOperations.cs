using System;
using System.Security.Cryptography.X509Certificates;

namespace app.CertificateStore
{
    public class CertificateStoreOperations
    {
        /// <summary>
        /// Find the target, not-expired, certificate by name from cert store. This is case-insensitive.
        /// </summary>
        /// <param name="certName"></param>
        /// <param name="storeLocation"></param>
        /// <param name="storeName"></param>
        /// <returns>X509Certificate2</returns>
        public X509Certificate2 FindNotExpiredCertFromCertStoreByName(string certName,
            StoreLocation storeLocation, StoreName storeName)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                var certCollection = store.Certificates;

                // Find all not-expired certs first.
                var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

                // Find the target.
                var targetCerts = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
                if (targetCerts.Count == 0)
                {
                    return null;
                }

                // Return the first certificate in the collection.
                return targetCerts[0];
            }
            finally
            {
                store?.Close();
                store?.Dispose();
            }
        }

        /// <summary>
        /// Find the target, not-expired, certificate by thumbprint from cert store. This is case-insensitive.
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="storeLocation"></param>
        /// <param name="storeName"></param>
        /// <returns>X509Certificate2</returns>
        public X509Certificate2 FindNotExpiredCertFromCertStoreByThumbprint(string thumbprint,
            StoreLocation storeLocation, StoreName storeName)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                var certCollection = store.Certificates;

                // Find all not-expired certs first.
                var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

                // Find the target.
                var targetCerts = currentCerts.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (targetCerts.Count == 0)
                {
                    return null;
                }

                // Return the first certificate in the collection.
                return targetCerts[0];
            }
            finally
            {
                store?.Close();
                store?.Dispose();
            }
        }

        /// <summary>
        /// Add target cert into cert store.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="storeLocation"></param>
        /// <param name="storeName"></param>
        public void AddCertificateIntoCertStore(X509Certificate2 cert,
            StoreLocation storeLocation, StoreName storeName)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);

                store.Add(cert);
            }
            finally
            {
                store?.Close();
                store?.Dispose();
            }
        }

        /// <summary>
        /// Remove target cert from cert store.
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="storeLocation"></param>
        /// <param name="storeName"></param>
        public void RemoveCertificateFromCertStore(X509Certificate2 cert,
            StoreLocation storeLocation, StoreName storeName)
        {
            X509Store store = null;
            try
            {
                store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);

                store.Remove(cert);
            }
            finally
            {
                store?.Close();
                store?.Dispose();
            }
        }
    }
}