//extern alias Fips;

//using Fips.Org.BouncyCastle.Asn1.Pkcs;
//using Fips.Org.BouncyCastle.Asn1.X509;
//using Fips.Org.BouncyCastle.Crypto.Asymmetric;
//using System;
//using System.Diagnostics;
//#nullable enable

//namespace Msp.Kms.Generators.BcFips
//{
//    public sealed class CsrSigner : CertBuilderBase, ICsrSigningService
//    {
//        public SigningResult Sign(
//               X509CertificateStructure signingCert,
//               AsymmetricECPrivateKey signatureKey,
//               CertificationRequest request,
//               SigningOptions opts)
//        {
//            if (signingCert is null)
//            {
//                throw new ArgumentNullException(nameof(signingCert)).Demystify();
//            }

//            if (signatureKey is null)
//            {
//                throw new ArgumentNullException(nameof(signatureKey)).Demystify();
//            }

//            if (request is null)
//            {
//                throw new ArgumentNullException(nameof(request)).Demystify();
//            }

//            if (opts is null)
//            {
//                throw new ArgumentNullException(nameof(opts)).Demystify();
//            }

//            var signed = SignAndValidate(signingCert, signatureKey, request, opts);

//            return BuildResult(signed, signingCert);
//        }

//        public SigningResult Sign(
//               byte[] signingCertBytes,
//               byte[] signatureKey,
//               byte[] requestAsPem,
//               SigningOptions opts)
//        {
//            if (signingCertBytes is null)
//            {
//                throw new ArgumentNullException(nameof(signingCertBytes)).Demystify();
//            }

//            if (signatureKey is null)
//            {
//                throw new ArgumentNullException(nameof(signatureKey)).Demystify();
//            }

//            if (requestAsPem is null)
//            {
//                throw new ArgumentNullException(nameof(requestAsPem)).Demystify();
//            }

//            if (opts is null)
//            {
//                throw new ArgumentNullException(nameof(opts)).Demystify();
//            }

//            var csr = CertificationRequest.GetInstance(CryptoHelpers.ExtractPemContent(requestAsPem));
//            var signingCert = X509CertificateStructure.GetInstance(signingCertBytes);
//            var sigKey = CryptoHelpers.CreatePrivateKey(signatureKey);

//            // SIGN
//            var signed = SignAndValidate(signingCert, sigKey, csr, opts);

//            return BuildResult(signed, signingCert); ;
//        }

//        private X509CertificateStructure SignAndValidate(
//            X509CertificateStructure signingCert,
//            AsymmetricECPrivateKey signatureKey,
//            CertificationRequest request,
//            SigningOptions opts)
//        {
//            EnsureFipsInit();

//            var req = request.GetCertificationRequestInfo();
//            var certPubKey = new AsymmetricECPublicKey(UsedAlgorithm, req.SubjectPublicKeyInfo.GetEncoded());

//            AddSubjectName(req.Subject);
//            AddIssuerFromSigningCert(signingCert);
//            AddStartEndDate(opts, signingCert);
//            AddSerialNumber();
//            AddPublicKey(certPubKey);
//            AddSignatureInfo(certPubKey);

//            // Certificate specific Extensions
//            var extensions = BuildCertExtensions();
//            AddExtensions(extensions);

//            return SignAndValidate(signingCert.SubjectPublicKeyInfo, signatureKey);
//        }

//        public string? ExtractCommonName(byte[] requestAsPem)
//        {
//            if (requestAsPem is null)
//            {
//                throw new ArgumentNullException(nameof(requestAsPem)).Demystify();
//            }

//            var subject = CertificationRequest.GetInstance(CryptoHelpers.ExtractPemContent(requestAsPem))
//                ?.GetCertificationRequestInfo()
//                ?.Subject;

//            return ExtractCommonName(subject);
//        }

//        public bool IsValidAlgorithm(byte[] requestAsPem)
//        {
//            var csr = CertificationRequest.GetInstance(CryptoHelpers.ExtractPemContent(requestAsPem));
//            return csr.SignatureAlgorithm.Algorithm.Id == Fips.Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.ECDsaWithSha256.Id; // currently only 1 allowed
//        }

//        public string? ExtractSubject(byte[] requestAsPem)
//        {
//            if (requestAsPem is null)
//            {
//                throw new ArgumentNullException(nameof(requestAsPem));
//            }

//            var subject = CertificationRequest.GetInstance(CryptoHelpers.ExtractPemContent(requestAsPem))
//                .GetCertificationRequestInfo()
//                .Subject;

//            return subject?.ToString();
//        }

//        private X509Extensions BuildCertExtensions()
//        {
//            var extBuilder = new X509ExtensionsGenerator();
//            extBuilder.AddExtension(X509Extensions.BasicConstraints, false, new BasicConstraints(false));

//            extBuilder.AddExtension(X509Extensions.KeyUsage, false,
//                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

//            extBuilder.AddExtension(X509Extensions.ExtendedKeyUsage, false,
//                new ExtendedKeyUsage(KeyPurposeID.IdKPClientAuth));

//            return extBuilder.Generate();
//        }

//        private void EnsureFipsInit() => ECKeyGenerator.Init();
//    }
//}
