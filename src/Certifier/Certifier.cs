using Dkbe.Certifier.Common.Models;
using Dkbe.Certifier.Fips;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

            var ecKeyGen = new Fips.KeyGenerators.ECKeyGenerator().GenerateKeyPair();

            var cert = new ClientCertBuilder(helpers)
                .BuildSelfSigned(ecKeyGen.PublicKey, ecKeyGen.PrivateKey, opts);

            return new X509Certificate2(cert.GetDerEncoded());
        }
    }
}
