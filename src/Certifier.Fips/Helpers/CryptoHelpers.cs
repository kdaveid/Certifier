extern alias Fips;

using Dkbe.Certifier.Fips.KeyGenerators;
using Fips.Org.BouncyCastle.Asn1;
using Fips.Org.BouncyCastle.Asn1.Pkcs;
using Fips.Org.BouncyCastle.Asn1.X509;
using Fips.Org.BouncyCastle.Asn1.X9;
using Fips.Org.BouncyCastle.Crypto;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using Fips.Org.BouncyCastle.Crypto.Fips;
using Fips.Org.BouncyCastle.Security;
using Fips.Org.BouncyCastle.Utilities.Encoders;
using Fips.Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace Dkbe.Certifier.Fips.Helpers
{
    /// <inheritdoc>/>
    public class CryptoHelpers : ICryptoHelpers
    {
        /// <inheritdoc>/>
        public byte[] ReadPemFile(string filePath)
        {
            if (filePath is null)
            {
                throw new ArgumentNullException(nameof(filePath)).Demystify();
            }

            using (var file = new StreamReader(filePath))
            {
                var reader = new PemReader(file);
                return reader.ReadPemObject().GetContent();
            }
        }

        /// <inheritdoc>/>
        public byte[] ExtractPemContent(byte[] pemBytes)
        {
            if (pemBytes is null)
            {
                throw new ArgumentNullException(nameof(pemBytes));
            }
            var pemString = Encoding.UTF8.GetString(pemBytes);
            using var ms = new StringReader(pemString);
            var reader = new PemReader(ms);
            return reader.ReadPemObject().GetContent();
        }

        /// <inheritdoc>/>
        public string ConvertToPemString(X509CertificateStructure cert)
        {
            if (cert is null)
            {
                throw new ArgumentNullException(nameof(cert)).Demystify();
            }

            using var sr = new StringWriter();
            var pem = new PemObject("CERTIFICATE", cert.GetDerEncoded());
            new PemWriter(sr).WriteObject(pem);
            return sr.ToString();
        }

        /// <inheritdoc>/>
        public string ConvertToPemString(string type, byte[] content)
        {
            if (type is null)
            {
                throw new ArgumentNullException(nameof(type)).Demystify();
            }

            if (content is null)
            {
                throw new ArgumentNullException(nameof(content)).Demystify();
            }

            using var sr = new StringWriter();
            var pem = new PemObject(type, content);
            new PemWriter(sr).WriteObject(pem);
            return sr.ToString();
        }

        /// <inheritdoc>/>
        public X509CertificateStructure ConvertCertificateFromPem(string pemCert)
        {
            if (pemCert is null)
            {
                throw new ArgumentNullException(nameof(pemCert)).Demystify();
            }

            using var sr = new StringReader(pemCert);
            var pw = new PemReader(sr);
            var pem = pw.ReadPemObject();

            if (pem == null)
            {
                throw new ApplicationException("could not read pem " + pemCert).Demystify();
            }

            return X509CertificateStructure.GetInstance(pem.GetContent());
        }

        /// <inheritdoc>/>
        public byte[] ConvertPemToBytes(string pemCert)
        {
            if (pemCert is null)
            {
                throw new ArgumentNullException(nameof(pemCert)).Demystify();
            }

            using var sr = new StringReader(pemCert);
            var pw = new PemReader(sr);
            var pem = pw.ReadPemObject();

            if (pem == null)
            {
                throw new ApplicationException("could not read pem " + pemCert).Demystify();
            }

            return X509CertificateStructure.GetInstance(pem.GetContent()).GetDerEncoded();
        }

        /// <inheritdoc>/>
        public CertificateList ConvertCrlFromPem(string pemCert)
        {
            if (pemCert is null)
            {
                throw new ArgumentNullException(nameof(pemCert)).Demystify();
            }

            using var sr = new StringReader(pemCert);
            var pw = new PemReader(sr);
            var pem = pw.ReadPemObject();

            if (pem == null)
            {
                throw new ApplicationException("could not read pem " + pemCert).Demystify();
            }

            return CertificateList.GetInstance(pem.GetContent());
        }

        public AsymmetricECPrivateKey CreatePrivateKey(byte[] privateKey)
        {
            var vKey = AsymmetricKeyFactory.CreatePrivateKey(privateKey);
            return new AsymmetricECPrivateKey(vKey.Algorithm, privateKey);
        }

        /// <inheritdoc>/>
        public SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricECPublicKey publicKey)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey)).Demystify();

            var x962 = BuildCurveParameters(publicKey.DomainParameters);
            var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, x962.ToAsn1Object());

            return new SubjectPublicKeyInfo(algID, publicKey.W.GetEncoded());
        }

        /// <inheritdoc>/>
        public SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricRsaPublicKey publicKey)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey)).Demystify();

            var info = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
                new RsaPublicKeyStructure(publicKey.Modulus, publicKey.PublicExponent).ToAsn1Object());

            return info;
        }

        /// <inheritdoc>/>
        public bool HasServerAuth(string certAsPem)
        {
            var ekuExt = GetExtendedKeyUsage(certAsPem);
            return ekuExt?.HasKeyPurposeId(KeyPurposeID.IdKPServerAuth) ?? false;
        }

        /// <inheritdoc>/>
        public bool HasClientAuth(string certAsPem)
        {
            var ekuExt = GetExtendedKeyUsage(certAsPem);
            return ekuExt?.HasKeyPurposeId(KeyPurposeID.IdKPClientAuth) ?? false;
        }


        private ExtendedKeyUsage? GetExtendedKeyUsage(string certAsPem)
        {
            var cert = X509CertificateStructure.GetInstance(ConvertCertificateFromPem(certAsPem));
            var ekuExt = cert.TbsCertificate.Extensions.GetExtension(X509Extensions.ExtendedKeyUsage);
            if (ekuExt == null)
            {
                return null;
            }
            return ExtendedKeyUsage.GetInstance(ekuExt.Value);
        }
        /// <inheritdoc>/>
        public string Fingerprint(X509CertificateStructure c, bool msCompatbileSha1 = false)
        {
            byte[] der = c.GetEncoded();

            if (!msCompatbileSha1)
            {
                return Fingerprint(Sha256DigestOf(der));
            }
            else
            {
                return Fingerprint(Sha1DigestOf(der));
            }
        }

        /// <inheritdoc>/>
        public string GetFingerprint(byte[] certificate, bool msCompatbileSha1 = false)
        {
            var cert = X509CertificateStructure.GetInstance(certificate);
            return Fingerprint(cert, msCompatbileSha1);
        }

        /// <inheritdoc>/>
        public string GetFingerprint(string certAsPem, bool msCompatbileSha1 = false)
        {
            var cert = X509CertificateStructure.GetInstance(ConvertCertificateFromPem(certAsPem));
            return Fingerprint(cert, msCompatbileSha1);
        }

        internal static string Fingerprint(byte[] sha)
        {
            byte[] hexBytes = Hex.Encode(sha);
            string hex = Encoding.ASCII.GetString(hexBytes).ToUpper(CultureInfo.InvariantCulture);

            StringBuilder fp = new StringBuilder();
            int i = 0;
            fp.Append(hex.Substring(i, 2));
            while ((i += 2) < hex.Length)
            {
                //fp.Append(':');
                fp.Append(hex.Substring(i, 2));
            }
            return fp.ToString();
        }

        internal static byte[] Sha256DigestOf(byte[] input) => DigestOf(CryptoServicesRegistrar.CreateService(FipsShs.Sha256).CreateCalculator(), input);

        internal static byte[] Sha1DigestOf(byte[] input) => DigestOf(CryptoServicesRegistrar.CreateService(FipsShs.Sha1).CreateCalculator(), input);

        internal static byte[] DigestOf(IStreamCalculator<IBlockResult> calc, byte[] input)
        {
            calc.Stream.Write(input, 0, input.Length);
            calc.Stream.Close();

            return calc.GetResult().Collect();
        }

        /// <inheritdoc>/>
        public AlgorithmIdentifier CreateSignatureAlgorithmIdentifier(AsymmetricECPublicKey publicKey)
        {
            if (publicKey == null) throw new ArgumentNullException(nameof(publicKey)).Demystify();

            var x962 = BuildCurveParameters(publicKey.DomainParameters);
            return new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256, x962.ToAsn1Object());
        }

        private static X962Parameters BuildCurveParameters(ECDomainParameters curveParams)
        {
            X962Parameters parameters;

            if (curveParams is NamedECDomainParameters)
            {
                parameters = new X962Parameters(((NamedECDomainParameters)curveParams).ID);
            }
            else if (curveParams is ECImplicitDomainParameters)
            {
                parameters = new X962Parameters(DerNull.Instance);
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                    curveParams.Curve,
                    curveParams.G,
                    curveParams.N,
                    curveParams.H,
                    curveParams.GetSeed());

                parameters = new X962Parameters(ecP);
            }

            return parameters;
        }

        /// <inheritdoc>/>
        public bool IsVerified(AsymmetricECPublicKey pubKey, byte[] signature, byte[] data)
        {
            var verifyer = CryptoServicesRegistrar.CreateService(pubKey)
                .CreateVerifierFactory(FipsEC.Dsa.WithDigest(FipsShs.Sha256));

            var verCalc = verifyer.CreateCalculator();

            using (var sOut = verCalc.Stream)
            {
                sOut.Write(data, 0, data.Length);
                sOut.Close();
            }

            return verCalc.GetResult().IsVerified(signature);
        }
    }
}
