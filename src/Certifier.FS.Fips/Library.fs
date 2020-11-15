namespace Certifier.FS.Fips

open System
open System.Text
open System.Linq
open Certifier.FS.Common.Models
open Org.BouncyCastle.Asn1.X509
open Org.BouncyCastle.Asn1
open Org.BouncyCastle.Asn1.X9
open Org.BouncyCastle.Crypto.Asymmetric
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Fips
open Org.BouncyCastle.Security

module CertBuilderModule =

    let DefaultEcKeyParams = ECDomainParametersIndex.LookupDomainParameters(Org.BouncyCastle.Crypto.Fips.FipsEC.DomainParams.P256)
    let GetECKeys namedParams = 
        let keyGenParams = new Org.BouncyCastle.Crypto.Fips.FipsEC.KeyGenerationParameters(namedParams)
        CryptoServicesRegistrar.CreateGenerator(keyGenParams).GenerateKeyPair();
    

    let BuildCurveParams (curveParams : ECDomainParameters) =
        new X962Parameters(new X9ECParameters(curveParams.Curve,curveParams.G,curveParams.N,curveParams.H,curveParams.GetSeed()))

    let ConvertPublicKeyToSubjectPublicKeyInfo (certPubKey : AsymmetricECPublicKey) =
        let algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, (BuildCurveParams certPubKey.DomainParameters))
        let spki = new SubjectPublicKeyInfo(algId, certPubKey.W.GetEncoded())
        spki

    let CheckValidityPeriod validityPeriod =
        validityPeriod.StartDateUtc < validityPeriod.EndDateUtc

    let GetCrlDistPoints urls =
        //let buildFileUrl url commonName =
        //    ""
            //match url.Last() with 
            //    | "/" -> ""
            //    | "" -> "/"
        // new GeneralName(GeneralName.UniformResourceIdentifier, "") // url
        // new DistributionPoint[] { new DistributionPoint(new DistributionPointName(new GeneralNames(gn)), null, null) }
        // let dispointArr : DistributionPoint array = Array.zeroCreate 1
        new CrlDistPoint(Array.zeroCreate 0)
        
    let signData (vKey : AsymmetricECPrivateKey) (data : byte[]) signatureParameters =
        let signatureFactoryProvider = CryptoServicesRegistrar.CreateService(vKey, new SecureRandom())
        let ecDsaSig = signatureFactoryProvider.CreateSignatureFactory(signatureParameters)
        let sigCalc = ecDsaSig.CreateCalculator()
        use sOut = sigCalc.Stream            
        sOut.Write(data, 0, data.Length);
        sOut.Close();
        sigCalc.GetResult().Collect()

    //let ClientCertExtensions distributionPointsExtension authorityIdent =
    let RootCaExtensions opts =
        let extBuilder = new X509ExtensionsGenerator()
        extBuilder.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(3)) |> ignore
        extBuilder.AddExtension(X509Extensions.KeyUsage, true, 
            new KeyUsage(KeyUsage.DigitalSignature &&& KeyUsage.KeyEncipherment &&& KeyUsage.KeyCertSign &&& KeyUsage.CrlSign)) |> ignore

        let extendedKeyUsage = new ExtendedKeyUsage([| KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth |]) 
        extBuilder.AddExtension(X509Extensions.ExtendedKeyUsage, false, extendedKeyUsage) |> ignore

        extBuilder.AddExtension(X509Extensions.CrlDistributionPoints, false, Array.zeroCreate 0) |> ignore
        //extBuilder.AddExtension(X509Extensions.CrlDistributionPoints, false, GetCrlDistPoints(opts)) |> ignore

        extBuilder.Generate()

    let VerifySignature (pubKey : AsymmetricECPublicKey) (signature : byte[]) (data : byte[]) (signatureParameters : IParameters<Algorithm>) = 
        let calculator = CryptoServicesRegistrar.CreateService(pubKey).CreateVerifierFactory(signatureParameters).CreateCalculator()
        use sOut = calculator.Stream
        sOut.Write(data, 0, data.Length)
        sOut.Close()
        calculator.GetResult().IsVerified(signature)


    let BuildSelfSignedCert certopts = 
        let generator = 
            new V3TbsCertificateGenerator()

        let keyMaterial = GetECKeys DefaultEcKeyParams

        let addStartEndDate (startDateUtc : DateTime) (endDateUtc : DateTime) =
            let derStartDate = new DerUtcTime (startDateUtc)
            let derEndDate = new DerUtcTime(endDateUtc)
            generator.SetStartDate(derStartDate) |> ignore
            generator.SetEndDate(derEndDate) |> ignore
            generator

        let addPublicKey certPubKey =
            generator.SetSubjectPublicKeyInfo(certPubKey) |> ignore
            generator

        let addExtensions extensions =
            generator.SetExtensions extensions
            generator

        let addSignatureInfo sigInfo=
            generator.SetSignature sigInfo
            generator

        let defaultSignatureParameters = FipsEC.Dsa.WithDigest(FipsShs.Sha256)

        let signAndValidate (vKey  : AsymmetricECPrivateKey, pKey : AsymmetricECPublicKey) = 
             let cert = generator.GenerateTbsCertificate()
             let dataToSign = cert.GetDerEncoded()
             let signature = signData vKey dataToSign defaultSignatureParameters 

             let verificationResult = VerifySignature pKey signature dataToSign defaultSignatureParameters

             new X509CertificateStructure(cert, cert.Signature, new DerBitString(signature))
        
        signAndValidate (keyMaterial.PrivateKey, keyMaterial.PublicKey)
        
