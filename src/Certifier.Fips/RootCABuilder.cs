extern alias Fips;

using Dkbe.Certifier.Common.Models;
using Dkbe.Certifier.Fips.Extensions;
using Dkbe.Certifier.Fips.Helpers;
using Fips.Org.BouncyCastle.Asn1.X509;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using System;
using System.Diagnostics;

namespace Dkbe.Certifier.Fips
{
    public sealed class RootCABuilder : CertBuilderBase
    {
        public RootCABuilder(ICryptoHelpers cryptoHelpers) : base(cryptoHelpers)
        {
        }

        public X509CertificateStructure Build(
            AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey> keyPair,
            RootCertOptions opts)
        {
            return Build(keyPair.PublicKey, keyPair.PrivateKey, opts);
        }

        public X509CertificateStructure Build(
            AsymmetricECPublicKey pKey,
            AsymmetricECPrivateKey vKey,
            RootCertOptions opts)
        {
            Validate(pKey, vKey);

            AddSubjectName(opts.CertOptions);
            SetSelfSigned(opts.CertOptions); // set subject = issuer --> self sign!
            AddStartEndDate(opts.CertOptions.ValidityPeriod.StartDateUtc, opts.CertOptions.ValidityPeriod.EndDateUtc);
            AddSerialNumber();
            AddPublicKey(pKey);
            AddSignatureInfo(pKey);

            // Certificate specific Extensions
            AddExtensions(GetRootCAExtensions(opts));

            // build root cert
            var cert = Builder.GenerateTbsCertificate().SubjectPublicKeyInfo;

            return SignAndValidate(cert, vKey);
        }

        private X509Extensions GetRootCAExtensions(RootCertOptions opts)
        {
            var extBuilder = new X509ExtensionsGenerator();
            extBuilder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(3));

            extBuilder.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            extBuilder.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                new ExtendedKeyUsage(new[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth }));

            extBuilder.AddExtension(X509Extensions.CrlDistributionPoints, false, GetCrlDistPoints(opts));

            return extBuilder.Generate();
        }

        private CrlDistPoint GetCrlDistPoints(RootCertOptions opts)
        {
            var gn = new GeneralName[opts.CrlUrls.Count];

            for (int i = 0; i < opts.CrlUrls.Count; i++)
            {
                var url = BuildCrlFileUrl(opts.CrlUrls[i], opts.CertOptions.CommonName);
                gn[i] = new GeneralName(GeneralName.UniformResourceIdentifier, url);
            }

            return new CrlDistPoint(new DistributionPoint[] { new DistributionPoint(new DistributionPointName(new GeneralNames(gn)), null, null) });
        }

        private static string BuildCrlFileUrl(string url, string commonName)
        {
            var delim = url.EndsWith("/") ? "" : "/";
            return $"{url}{delim}{commonName.UrlSafe()}.crl";
        }

        private void Validate(
            AsymmetricECPublicKey pKey,
            AsymmetricECPrivateKey vKey)
        {
            if (pKey == null)
            {
                throw new ArgumentNullException(nameof(pKey)).Demystify();
            }

            if (vKey == null)
            {
                throw new ArgumentNullException(nameof(vKey)).Demystify();
            }
        }
    }
}
