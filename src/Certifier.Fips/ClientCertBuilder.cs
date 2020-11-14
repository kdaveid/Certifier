extern alias Fips;

using Dkbe.Certifier.Common.Models;
using Dkbe.Certifier.Fips.Helpers;
using Fips.Org.BouncyCastle.Asn1;
using Fips.Org.BouncyCastle.Asn1.X509;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using System;
using System.Diagnostics;

namespace Dkbe.Certifier.Fips
{
    public sealed class ClientCertBuilder : CertBuilderBase
    {
        public ClientCertBuilder(ICryptoHelpers cryptoHelpers) : base(cryptoHelpers)
        {
        }

        public CertBuilderResult Build(
            X509CertificateStructure signingCert,
            AsymmetricECPrivateKey signatureKey,
            AsymmetricECPublicKey certPubKey,
            CertOptions opts)
        {
            Validate(signingCert, signatureKey);

            AddSubjectName(opts);
            AddIssuerFromSigningCert(signingCert);
            AddStartEndDate(opts, signingCert);
            AddSerialNumber();
            AddPublicKey(certPubKey);
            AddSignatureInfo(signingCert.SignatureAlgorithm);

            var dpExtensionObject = GetDistributionPointExtensionObject(signingCert);
            var authorityKeyIdent = new AuthorityKeyIdentifier(signingCert.SubjectPublicKeyInfo);
            var extensions = BuildCertExtensions(dpExtensionObject, authorityKeyIdent);

            // Certificate specific Extensions
            AddExtensions(extensions);

            var signed = SignAndValidate(signingCert.SubjectPublicKeyInfo, signatureKey);

            return BuildResult(signed, signingCert); ;
        }

        public CertBuilderResult Build(
            X509CertificateStructure signingCert,
            AsymmetricECPrivateKey signatureKey,
            AsymmetricRsaPublicKey certPubKey,
            CertOptions opts)
        {
            Validate(signingCert, signatureKey);

            AddSubjectName(opts);
            AddIssuerFromSigningCert(signingCert);
            AddStartEndDate(opts, signingCert);
            AddSerialNumber();
            AddPublicKey(certPubKey);
            AddSignatureInfo(signingCert.SignatureAlgorithm);

            var dpExtensionObject = GetDistributionPointExtensionObject(signingCert);
            var authorityKeyIdent = new AuthorityKeyIdentifier(signingCert.SubjectPublicKeyInfo);
            var extensions = BuildCertExtensions(dpExtensionObject, authorityKeyIdent);

            // Certificate specific Extensions
            AddExtensions(extensions);

            var signed = SignAndValidate(signingCert.SubjectPublicKeyInfo, signatureKey);

            return BuildResult(signed, signingCert); ;
        }

        public X509CertificateStructure BuildSelfSigned(
            AsymmetricECPublicKey pKey,
            AsymmetricECPrivateKey vKey,
            CertOptions opts)
        {
            if (pKey is null)
            {
                throw new ArgumentNullException(nameof(pKey));
            }

            if (vKey is null)
            {
                throw new ArgumentNullException(nameof(vKey));
            }

            AddSubjectName(opts);
            SetSelfSigned(opts); // set subject = issuer --> self sign!
            AddStartEndDate(opts.ValidityPeriod.StartDateUtc, opts.ValidityPeriod.EndDateUtc);
            AddSerialNumber();
            AddPublicKey(pKey);
            AddSignatureInfo(pKey);

            var extensions = BuildSelfSignedCertExtensions();

            // Certificate specific Extensions
            AddExtensions(extensions);

            var selfSigned = Builder.GenerateTbsCertificate().SubjectPublicKeyInfo;

            return SignAndValidate(selfSigned, vKey);
        }

        private X509Extensions BuildSelfSignedCertExtensions()
        {
            var extBuilder = new X509ExtensionsGenerator();
            extBuilder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

            extBuilder.AddExtension(X509Extensions.KeyUsage, false,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

            extBuilder.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));

            return extBuilder.Generate();
        }

        private X509Extensions BuildCertExtensions(Asn1Encodable? distributionPointsExtensionObject, AuthorityKeyIdentifier ident)
        {
            var extBuilder = new X509ExtensionsGenerator();
            extBuilder.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));

            extBuilder.AddExtension(X509Extensions.KeyUsage, false,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

            extBuilder.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));

            // key ident
            extBuilder.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, ident);

            // Adding CRL distribution point from signing cert
            if (distributionPointsExtensionObject != null)
            {
                extBuilder.AddExtension(X509Extensions.CrlDistributionPoints, false, distributionPointsExtensionObject);
            }

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
