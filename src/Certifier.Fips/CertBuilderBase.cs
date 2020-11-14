extern alias Fips;

using Dkbe.Certifier.Common.Models;
using Dkbe.Certifier.Fips.Helpers;
using Fips.Org.BouncyCastle.Asn1;
using Fips.Org.BouncyCastle.Asn1.X500;
using Fips.Org.BouncyCastle.Asn1.X500.Style;
using Fips.Org.BouncyCastle.Asn1.X509;
using Fips.Org.BouncyCastle.Crypto;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using Fips.Org.BouncyCastle.Crypto.Fips;
using Fips.Org.BouncyCastle.Math;
using Fips.Org.BouncyCastle.Security;
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Dkbe.Certifier.Fips
{
    public abstract class CertBuilderBase
    {
        protected readonly V3TbsCertificateGenerator Builder = new V3TbsCertificateGenerator();
        protected readonly Algorithm UsedAlgorithm = FipsEC.Alg;

        protected ICryptoHelpers CryptoHelpers { get; }

        public CertBuilderBase(ICryptoHelpers cryptoHelpers)
        {
            CryptoHelpers = cryptoHelpers;
        }

        protected void AddStartEndDate(CertOptions opts, X509CertificateStructure signingCert)
        {
            var notBefore = opts.ValidityPeriod.StartDateUtc;
            if (notBefore < signingCert.StartDate.ToDateTime())
            {
                notBefore = signingCert.StartDate.ToDateTime();
            }

            var notAfter = opts.ValidityPeriod.EndDateUtc;
            if (notAfter > signingCert.EndDate.ToDateTime())
            {
                notAfter = signingCert.EndDate.ToDateTime();
            }

            Builder.SetStartDate(new DerUtcTime(notBefore));
            Builder.SetEndDate(new DerUtcTime(notAfter));
        }

        protected void AddStartEndDate(DateTime start, DateTime end)
        {
            Builder.SetStartDate(new DerUtcTime(start));
            Builder.SetEndDate(new DerUtcTime(end));
        }

        protected void AddPublicKey(AsymmetricECPublicKey certPubKey)
        {
            var publicKeyInfo = CryptoHelpers.CreateSubjectPublicKeyInfo(certPubKey);
            Builder.SetSubjectPublicKeyInfo(publicKeyInfo);
        }

        protected void AddSignatureInfo(AsymmetricECPublicKey certPubKey)
        {
            var sigAlgo = CryptoHelpers.CreateSignatureAlgorithmIdentifier(certPubKey);
            Builder.SetSignature(sigAlgo);
        }

        protected void AddSignatureInfo(AlgorithmIdentifier signatureAlgo)
        {
            Builder.SetSignature(signatureAlgo);
        }

        protected void AddPublicKey(AsymmetricRsaPublicKey certPubKey)
        {
            var publicKeyInfo = CryptoHelpers.CreateSubjectPublicKeyInfo(certPubKey);
            Builder.SetSubjectPublicKeyInfo(publicKeyInfo);
        }

        protected void AddExtensions(X509Extensions extensions)
        {
            Builder.SetExtensions(extensions);
        }

        protected static Asn1Encodable? GetDistributionPointExtensionObject(X509CertificateStructure signingCert)
        {
            var ext = signingCert.TbsCertificate.Extensions.GetExtension(X509Extensions.CrlDistributionPoints);
            return ext?.GetParsedValue(); // TODO: backwards compatibility - remove null check
        }

        protected static AuthorityKeyIdentifier GetAuthorityKeyIdentifier(X509CertificateStructure signingCert)
        {
            return new AuthorityKeyIdentifier(
                signingCert.SubjectPublicKeyInfo, 
                new GeneralNames(new GeneralName(signingCert.TbsCertificate.Issuer)), 
                signingCert.SerialNumber.Value);
        }

        protected void AddSerialNumber()
        {
            // fixed length serial number for TPM/ATECC Chip: 11 bytes
            var timeStampBytes = BitConverter.GetBytes(GetUnixTimestamp());

            if (timeStampBytes.Length > 11)
            {
                throw new ArgumentOutOfRangeException("serial number must be smaller than 20 bytes").Demystify();
            }

            var trgtArr = new byte[11]; // zero byte arr
            var startAt = trgtArr.Length - timeStampBytes.Length;

            Array.Copy(timeStampBytes, 0, trgtArr, startAt, timeStampBytes.Length);

            Builder.SetSerialNumber(new DerInteger(new BigInteger(trgtArr)));
        }

        protected X509CertificateStructure SignAndValidate(SubjectPublicKeyInfo signingCertPublicKeyInfo, AsymmetricECPrivateKey signingKey)
        {
            var signingCertPublicKey = new AsymmetricECPublicKey(FipsEC.Alg, signingCertPublicKeyInfo);

            // build cert
            var cert = Builder.GenerateTbsCertificate();

            // sign
            var signature = SignData(signingKey, cert.GetDerEncoded());

            // check signature
            if (!CryptoHelpers.IsVerified(signingCertPublicKey, signature, cert.GetDerEncoded()))
            {
                throw new ApplicationException("signature validation failed").Demystify();
            }

            return new X509CertificateStructure(cert, cert.Signature, new DerBitString(signature));
        }

        private static byte[] SignData(AsymmetricECPrivateKey privKey, byte[] data)
        {
            if (!CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new ApplicationException("you have to be in approved mode!").Demystify();
            }

            var signatureFactoryProvider = CryptoServicesRegistrar.CreateService(privKey, new SecureRandom());
            var ecDsaSig = signatureFactoryProvider.CreateSignatureFactory(FipsEC.Dsa.WithDigest(FipsShs.Sha256));
            var sigCalc = ecDsaSig.CreateCalculator();

            using (var sOut = sigCalc.Stream)
            {
                sOut.Write(data, 0, data.Length);
                sOut.Close();
            }

            return sigCalc.GetResult().Collect();
        }

        protected void AddSubjectName(CertOptions opts)
        {
            Builder.SetSubject(GenerateSubjectName(opts));
        }

        protected void AddSubjectName(X500Name subject)
        {
            Builder.SetSubject(subject);
        }

        protected static X500Name GenerateSubjectName(CertOptions opts)
        {
            var subject = new X500NameBuilder(BCStrictStyle.Instance);

            if (!string.IsNullOrEmpty(opts.Country))
                subject.AddRdn(BCStrictStyle.C, opts.Country);

            if (!string.IsNullOrEmpty(opts.Organization))
                subject.AddRdn(BCStrictStyle.O, opts.Organization);

            if (!string.IsNullOrEmpty(opts.OrganizationUnit))
                subject.AddRdn(BCStrictStyle.OU, opts.OrganizationUnit);

            if (!string.IsNullOrEmpty(opts.CommonName))
                subject.AddRdn(BCStrictStyle.CN, opts.CommonName);

            return subject.Build();
        }

        protected void SetSelfSigned(CertOptions opts)
        {
            Builder.SetIssuer(GenerateSubjectName(opts));
        }

        protected void AddIssuerFromSigningCert(X509CertificateStructure signingCert)
        {
            Builder.SetIssuer(signingCert.TbsCertificate.Issuer);
        }

        public static X509Certificate2 Convert(X509CertificateStructure selfSignedCert)
        {
            return new X509Certificate2(selfSignedCert.GetDerEncoded());
        }

        protected CertBuilderResult BuildResult(X509CertificateStructure signed, X509CertificateStructure issuer)
        {
            var certAsPem = CryptoHelpers.ConvertToPemString(signed);
            var certAsString = CertOutParser.ParseOut(certAsPem);
            var thumbPrint = CryptoHelpers.Fingerprint(signed, false);
            var thumbPrintMsCompatible = CryptoHelpers.Fingerprint(signed, true);

            return new CertBuilderResult
            {
                CommonName = ExtractCommonName(signed.TbsCertificate.Subject) ?? "none",
                Subject = signed.TbsCertificate.Subject.ToString(),
                Thumbprint = thumbPrint,
                ThumbprintMS = thumbPrintMsCompatible,
                SerialNumber = signed.SerialNumber.Value.LongValue,
                SignedCertAsPem = certAsPem,
                NotBefore = signed.StartDate.ToDateTime().ToUniversalTime(),
                NotAfter = signed.EndDate.ToDateTime().ToUniversalTime(),
                SignedCertBytes = signed.GetEncoded(),
                IssuerCertBytes = issuer.GetEncoded(),
                HumanReadableCertString = certAsString,
            };
        }

        protected string? ExtractCommonName(X500Name? subject) =>
            subject?.GetRdns()
                ?.Select(s => s.First)
                ?.FirstOrDefault(s => s.Type.Id == Rfc4519Style.cn.Id)
                ?.Value
                ?.ToString();

        private static double GetUnixTimestamp()
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return System.Convert.ToInt64((DateTime.UtcNow - epoch).TotalSeconds);
        }
    }
}
