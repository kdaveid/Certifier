extern alias Fips;

using Dkbe.Certifier.Common.Models;
using Dkbe.Certifier.Fips;
using Dkbe.Certifier.Fips.Helpers;
using Fips.Org.BouncyCastle.Asn1;
using Fips.Org.BouncyCastle.Asn1.X509;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Msp.Kms.Generators.BcFips
{
    public sealed class ServerCertBuilder : CertBuilderBase
    {
        public ServerCertBuilder(ICryptoHelpers cryptoHelpers) : base(cryptoHelpers)
        {
        }

        public CertBuilderResult Build(
            X509CertificateStructure signingCert,
            AsymmetricECPrivateKey signingKey,
            AsymmetricECPublicKey certPubKey,
            CertOptions opts)
        {
            Validate(signingCert, signingKey);

            AddSubjectName(opts);
            AddIssuerFromSigningCert(signingCert);
            AddStartEndDate(opts, signingCert);
            AddSerialNumber();
            AddPublicKey(certPubKey);
            AddSignatureInfo(certPubKey);

            var dpExtensionObject = GetDistributionPointExtensionObject(signingCert);
            var authorityKeyIdent = GetAuthorityKeyIdentifier(signingCert);

            // Certificate specific Extensions
            AddExtensions(ServerCertExtensions(opts, dpExtensionObject, authorityKeyIdent));

            var signed = SignAndValidate(signingCert.SubjectPublicKeyInfo, signingKey);

            return BuildResult(signed, signingCert); ;
        }

        private X509Extensions ServerCertExtensions(CertOptions opts, Asn1Encodable? dpEO, AuthorityKeyIdentifier ident)
        {
            var extBuilder = new X509ExtensionsGenerator();
            extBuilder.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));

            extBuilder.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment | KeyUsage.DigitalSignature));

            extBuilder.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth));

            var names = new List<GeneralName>();
            foreach (var san in opts.SubjectAlternativeNames)
            {
                names.Add(new GeneralName(GeneralName.DnsName, san));
            }

            extBuilder.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(names.ToArray()));

            // key ident
            extBuilder.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, ident);

            //// Adding CRL distribution point from signing cert
            //if (dpEO != null)
            //{
            //    extBuilder.AddExtension(X509Extensions.CrlDistributionPoints, false, dpEO);
            //}

            return extBuilder.Generate();
        }

        private void Validate(X509CertificateStructure sigingCert, AsymmetricECPrivateKey vKey)
        {
            if (sigingCert == null)
            {
                throw new ArgumentNullException(nameof(sigingCert)).Demystify();
            }

            if (vKey == null)
            {
                throw new ArgumentNullException(nameof(vKey)).Demystify();
            }
        }
    }
}
