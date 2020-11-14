extern alias Fips;

using Fips.Org.BouncyCastle.Crypto;
using Fips.Org.BouncyCastle.Crypto.Asymmetric;
using Fips.Org.BouncyCastle.Crypto.Fips;
using Fips.Org.BouncyCastle.Math;
using System;
using System.Diagnostics;

namespace Dkbe.Certifier.Fips.KeyGenerators
{
    public class RsaKeyGenerator : KeyGeneratorBase
    {
        private static readonly FipsRsa.KeyGenerationParameters UsedKeyPairParams =
            new FipsRsa.KeyGenerationParameters(BigInteger.ValueOf(0x10001), 2048);

        public AsymmetricKeyPair<AsymmetricRsaPublicKey, AsymmetricRsaPrivateKey> GenerateKeyPair()
        {
            if (!CryptoServicesRegistrar.IsInApprovedOnlyMode())
            {
                throw new ApplicationException("you have to be in approved mode!").Demystify();
            }

            return CryptoServicesRegistrar.CreateGenerator(UsedKeyPairParams).GenerateKeyPair();
        }
    }
}
