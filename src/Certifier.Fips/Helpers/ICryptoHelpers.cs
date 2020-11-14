extern alias Fips;
using Fips.Org.BouncyCastle.Asn1.X509;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using System;

namespace Dkbe.Certifier.Fips.Helpers
{
    public interface ICryptoHelpers
    {
        /// <summary>
        /// Reading a cert file as PemObject (DER)
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        byte[] ReadPemFile(string filePath);

        /// <summary>
        /// Reading a cert file as PemObject (DER)
        /// </summary>
        /// <param name="pemBytes"></param>
        /// <returns></returns>
        byte[] ExtractPemContent(byte[] pemBytes);

        /// <summary>
        /// Converts a <see cref="X509CertificateStructure"/> to a PEM object string that can be saved to a file
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        string ConvertToPemString(X509CertificateStructure cert);

        /// <summary>
        /// Saves cert or private key content to a PEM file 
        /// </summary>
        /// <param name="type">i.E. CERTIFICATE or EC PRIVATE KEY ...</param>
        /// <param name="content"></param>
        /// <returns></returns>
        string ConvertToPemString(string type, byte[] content);

        /// <summary>
        /// Converts a PEM formatted X509 certificate to a <see cref="X509CertificateStructure"/> 
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        X509CertificateStructure ConvertCertificateFromPem(string pemCert);

        /// <summary>
        /// Converts a  to a raw byte array
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        byte[] ConvertPemToBytes(string pemCert);

        /// <summary>
        /// Converts a  to a <see cref="X509CertificateStructure"/> 
        /// </summary>
        /// <param name="cert"></param>
        /// <returns></returns>
        CertificateList ConvertCrlFromPem(string pemCert);

        ///// <summary>
        ///// Converts a given private key byte array to a <see cref="AsymmetricECPrivateKey"/>
        ///// </summary>
        ///// <param name="privateKey"></param>
        ///// <returns></returns>
        //AsymmetricECPrivateKey CreatePrivateKey(byte[] privateKey);

        /// <summary>
        /// Create a Subject Public Key Info object for a given public key.
        /// </summary>
        /// <param name="publicKey">Only ECPublicKey supported</param>
        /// <returns>A subject public key info object.</returns>
        /// <exception cref="Exception">Throw exception if object provided is not one of the above.</exception>
        SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricECPublicKey publicKey);

        /// <summary>
        /// Create a Subject Public Key Info object for a given public key.
        /// </summary>
        /// <param name="publicKey">Only ECPublicKey supported</param>
        /// <returns>A subject public key info object.</returns>
        /// <exception cref="Exception">Throw exception if object provided is not one of the above.</exception>
        SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricRsaPublicKey publicKey);

        /// <summary>
        /// Get SigAlgoIdent from public key
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        AlgorithmIdentifier CreateSignatureAlgorithmIdentifier(AsymmetricECPublicKey publicKey);

        bool HasServerAuth(string certAsPem);

        bool HasClientAuth(string certAsPem);

        string Fingerprint(X509CertificateStructure c, bool msCompatbileSha1 = false);

        string GetFingerprint(byte[] certificate, bool msCompatbileSha1 = false);

        string GetFingerprint(string certAsPem, bool msCompatbileSha1 = false);

        /// <summary>
        /// Verify signed data signature against a public key
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="signature"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        bool IsVerified(AsymmetricECPublicKey pubKey, byte[] signature, byte[] data);
    }
}