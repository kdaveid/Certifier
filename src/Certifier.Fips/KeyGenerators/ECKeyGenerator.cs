extern alias Fips;

using Fips.Org.BouncyCastle.Crypto;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using Fips::Org.BouncyCastle.Crypto.Fips;
using System;
using System.Diagnostics;

namespace Dkbe.Certifier.Fips.KeyGenerators
{
    public class ECKeyGenerator : KeyGeneratorBase
    {
        private static readonly FipsEC.KeyGenerationParameters UsedKeyPairParams =
           new FipsEC.KeyGenerationParameters(ECDomainParametersIndex.LookupDomainParameters(FipsEC.DomainParams.P256));

        public AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey> GenerateKeyPair()
        {
            if (!CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new ApplicationException("you have to be in approved mode!").Demystify();
            }

            return CryptoServicesRegistrar.CreateGenerator(UsedKeyPairParams).GenerateKeyPair();
        }
    }
}
