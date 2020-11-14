using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Dkbe.Certifier.Storage
{

    public static class BouncyCastleStorage
    {
        /// <summary>
        /// Convert a Bouncy Castle KeyPair from fips1.0.1 to new world
        /// </summary>
        /// <param name="rootCaCertAsSubjectPublicKeyInfo"></param>
        /// <param name="vKeyAsString"></param>
        /// <returns></returns>
        public static AsymmetricCipherKeyPair ConvertBouncyCastleKeyPair(byte[] rootCaCertAsSubjectPublicKeyInfo, string vKeyAsString)
        {
            var pKey = PublicKeyFactory.CreateKey(rootCaCertAsSubjectPublicKeyInfo);
            var vKey = ConvertBouncyCastlePrivateKey(vKeyAsString);

            return new AsymmetricCipherKeyPair(pKey, vKey);
        }

        /// <summary>
        /// Convert a Bouncy Castle Private Key from fips1.0.1 to new world
        /// </summary>
        /// <param name="vKeyAsString">PEM serialized Private Key</param>
        /// <returns></returns>
        public static AsymmetricKeyParameter ConvertBouncyCastlePrivateKey(string vKeyAsString)
        {
            using (var sr = new StringReader(vKeyAsString))
            {
                var reader = new PemReader(sr);
                var bytes = reader.ReadPemObject().Content;
                return PrivateKeyFactory.CreateKey(bytes);
            }
        }

        /// <summary>
        /// Encrypt and store a Bouncy Castle certificate <see cref="X509Certificate"/> in a PKCS12 secret store
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="privateKey"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static void StoreToFile(X509Certificate certificate, AsymmetricKeyParameter privateKey, X509Certificate[]? chain, string? password, string? filePath)
        {
            if (filePath is null)
            {
                throw new ArgumentNullException(nameof(filePath));
            }

            var store = (File.Exists(filePath) && new FileInfo(filePath).Length > 0)
                      ? LoadStore(password, filePath)
                      : CreateEmptyKeyStore(password, filePath);

            Add(store, certificate, privateKey, chain);

            // CreateBase64FromStore(store);

            SaveStore(store, password, filePath);
        }

        /// <summary>
        /// Encrypt and store a Bouncy Castle certificate <see cref="X509Certificate"/> in a PKCS12 secret store
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="privateKey"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static byte[] StoreInMemory(X509Certificate certificate, AsymmetricKeyParameter privateKey, X509Certificate[]? chain, string? password)
        {
            using (var inMemStore = new MemoryStream())
            using (var stored = new MemoryStream())
            {
                var store = CreateEmptyKeyStore(password, inMemStore);
                Add(store, certificate, privateKey, chain);

                SaveStore(store, password, stored);

                // CreateBase64FromStore(store);

                return stored.ToArray();
            }
        }

        public static byte[] AddCert(byte[] storeBytes, X509Certificate certificate, string password)
        {
            using (var inMemStore = new MemoryStream(storeBytes))
            using (var stored = new MemoryStream())
            {
                var store = new Pkcs12Store(inMemStore, password.ToCharArray());
                AddCert(store, certificate);

                SaveStore(store, password, stored);

                return stored.ToArray();
            }
        }

        public static Pkcs12Store CreateEmptyKeyStore(string? password, string filePath)
        {
            using var stream = File.OpenWrite(filePath);
            return CreateEmptyKeyStore(password, stream);
        }

        public static Pkcs12Store CreateEmptyKeyStore(string? password, Stream stream)
        {
            var store = new Pkcs12Store();

            store.Save(stream, password?.ToCharArray() ?? null, new SecureRandom());

            return store;
        }

        /// <summary>
        /// Load and decrypt a single Bouncy Castle certificate <see cref="X509Certificate"/> from a PKCS12 secret store
        /// </summary>
        /// <returns></returns>
        public static (byte[]? Cert, byte[]? Key) GetPair(string alias, string password, Stream stream)
        {
            if (alias is null)
            {
                throw new ArgumentNullException(nameof(alias)).Demystify();
            }

            if (password is null)
            {
                throw new ArgumentNullException(nameof(password)).Demystify();
            }

            var store = LoadStore(password, stream);

            var cert = store.GetCertificate(alias).Certificate;
            var key = store.GetKey(alias)?.Key;
            var pki = key != null ? PrivateKeyInfoFactory.CreatePrivateKeyInfo(key) : null;

            return (cert?.GetEncoded(), pki?.GetDerEncoded());
        }

        private static Pkcs12Store LoadStore(string? password, string filePath)
        {
            using var stream = File.OpenRead(filePath);
            return LoadStore(password, stream);
        }

        private static Pkcs12Store LoadStore(string? password, Stream stream)
        {
            var store = new Pkcs12Store();

            try
            {
                store.Load(stream, password?.ToCharArray() ?? null);
            }
            catch (IOException ex)
            {
                throw new StorageException("cannot open store because of an IO issue", ex);
            }
            catch (Exception ex)
            {
                throw new StorageException("cannot open store", ex);
            }
            finally
            {
                stream.Close();
            }

            return store;
        }

        /// <summary>
        /// Tries to load store from filestream with the given password
        /// </summary>
        /// <param name="password"></param>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static bool CanOpenStore(string password, Stream stream)
        {
            var store = new Pkcs12Store();

            try
            {
                store.Load(stream, password.ToCharArray());
            }
            catch (IOException)
            {
                // since we have read a stream, the file must be there and we can assume that the given password is wrong
                throw new StorageException("cannot open store with given password", unsealException: true).Demystify();
            }
            catch (Exception ex)
            {
                throw new StorageException(ex.Message);
            }
            finally
            {
                stream.Close();
            }

            return store != null;
        }

        /// <summary>
        /// Load and encrypt a Bouncy Castle store and get all certificates from the PKCS12 secret store
        /// </summary>
        /// <param name="password"></param>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static IEnumerable<X509Certificate> GetAllCertificates(string password, string filePath)
        {
            var store = LoadStore(password, filePath);
            return GetAll(store).Certs.Select(s => s.Certificate).ToList();
        }

        /// <summary>
        /// Load and encrypt a Bouncy Castle store and get all certificates from the PKCS12 secret store
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="privateKey"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static IEnumerable<X509Certificate> GetAllCertificates(string password, Stream stream)
        {
            var store = LoadStore(password, stream);
            return GetAll(store).Certs.Select(s => s.Certificate).ToList();
        }

        private static (IEnumerable<X509CertificateEntry> Certs, IEnumerable<AsymmetricKeyEntry> Keys) GetAll(Pkcs12Store store)
        {
            var enumer = store.Aliases.GetEnumerator();

            var certs = new List<X509CertificateEntry>();
            var keys = new List<AsymmetricKeyEntry>();

            X509CertificateEntry c;
            AsymmetricKeyEntry k;

            while (enumer.MoveNext())
            {
                var alias = (string)enumer.Current;

                c = store.GetCertificate(alias);
                if (c != null)
                {
                    certs.Add(c);
                }

                k = store.GetKey(alias);
                if (k != null)
                {
                    keys.Add(k);
                }
            }
            return (certs, keys);
        }

        private static Pkcs12Store Add(Pkcs12Store store, X509Certificate bcCert, AsymmetricKeyParameter vKey, X509Certificate[]? chain)
        {
            var alias = bcCert.SerialNumber.ToString();

            if (store.ContainsAlias(alias))
            {
                // already in store
                return store;
            }

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(bcCert);
            store.SetCertificateEntry(alias, certificateEntry);

            // Attach certs to key
            var entries = new List<X509CertificateEntry>
            {
                certificateEntry
            };

            chain?.ToList().ForEach(cert => entries.Add(new X509CertificateEntry(cert)));

            // Add the private key under the same alias as the certificate
            store.SetKeyEntry(alias, new AsymmetricKeyEntry(vKey), entries.ToArray());

            return store;
        }

        private static Pkcs12Store AddCert(Pkcs12Store store, X509Certificate bcCert)
        {
            var alias = bcCert.SerialNumber.ToString();

            if (store.ContainsAlias(alias))
            {
                // already in store
                return store;
            }

            // Add the certificate.
            var certificateEntry = new X509CertificateEntry(bcCert);

            store.SetCertificateEntry(alias, certificateEntry);

            return store;
        }

        private static void SaveStore(Pkcs12Store store, string password, string filePath)
        {
            using (var stream = File.OpenWrite(filePath))
            {
                store.Save(stream, password.ToCharArray(), new SecureRandom());
            }
        }

        private static void SaveStore(Pkcs12Store store, string password, Stream stream)
        {
            store.Save(stream, null, new SecureRandom());
            //store.Save(stream, password.ToCharArray(), new SecureRandom());
        }

        /// <summary>
        /// Used to update unit tests
        /// </summary>
        /// <param name="store"></param>
#pragma warning disable IDE0051 // Remove unused private members
        private static void CreateBase64FromStore(Pkcs12Store store)
#pragma warning restore IDE0051 // Remove unused private members
        {
            using var mem = new MemoryStream();
            store.Save(mem, "633ca6e6187d".ToCharArray(), new SecureRandom());

            var base64 = Convert.ToBase64String(mem.ToArray());
        }
    }
}

