using Dkbe.Certifier.Common.Models;
using Dkbe.Certifier.Fips;
using Dkbe.Certifier.Storage;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Dkbe.Certifier
{
    public class Certifier
    {
        public X509Certificate2? CreateSelfSignedCertificate(string commonName)
        {
            var helpers = new Fips.Helpers.CryptoHelpers();

            var opts = CertOptions.CreateCertificateOptions(
                ValidityPeriod.CreateDefaultValidityPeriod,
                commonName, "", "", "", null, null);

            if (!opts.IsValid())
            {
                opts.ValidationErrors().ToList().ForEach(s => Console.WriteLine("Error occured: " + s));
                return null;
            }

            // Generate keys
            var ecKeyGen = new Fips.KeyGenerators.ECKeyGenerator().GenerateKeyPair();

            // Generate cert
            var fipsCert = new ClientCertBuilder(helpers).BuildSelfSigned(ecKeyGen.PublicKey, ecKeyGen.PrivateKey, opts);

            // Convert from FIPS to new BouncyCastle
            var bcKey = BouncyCastleStorage.ConvertBouncyCastlePrivateKey(helpers.ConvertToPemString("EC PRIVATE KEY", ecKeyGen.PrivateKey.GetEncoded()));
            var bcCert = new Org.BouncyCastle.X509.X509Certificate(Org.BouncyCastle.Asn1.X509.X509CertificateStructure.GetInstance(fipsCert.GetDerEncoded()));

            // Store
            var storageMem = BouncyCastleStorage.StoreInMemory(bcCert, bcKey, null, null);

            //File.WriteAllBytes("cert_ec.p12", storageMem);
            //var viaFs = new X509Certificate2("cert_ec.p12");

            return new X509Certificate2(storageMem); ;
        }
    }
}
