extern alias Fips;

using Fips::Org.BouncyCastle.Crypto;
using Fips::Org.BouncyCastle.Crypto.Fips;
using Fips::Org.BouncyCastle.Security;
using Fips::Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Dkbe.Certifier.Fips.KeyGenerators
{
    public class KeyGeneratorBase
    {
        protected const string HEX_DIGEST_FIPS_1_0_1 = "b814dd227eb1fe24d6b92a6988b8b029e0f7957d3ddaee36c6a34f0d1161d5db";

        internal KeyGeneratorBase()
        {
            Init();
        }

        public static void Init()
        {
            CryptoServicesRegistrar.SetApprovedOnlyMode(true);
            InitRandom();
            VerifyIntegrity();
            CryptoStatus.IsReady();
        }

        public SecureRandom GetRandom()
        {
            return new SecureRandom();
        }

        private static void InitRandom()
        {
            // initialization vector
            var personalizationString = Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString());

            // build "random" random
            var entropySource = new SecureRandom();

            var random = CryptoServicesRegistrar.CreateService(FipsDrbg.Sha512)
                                    .FromEntropySource(entropySource, true)
                                    .SetPersonalizationString(personalizationString)
                                    .Build(
                                    entropySource.GenerateSeed((256 / (2 * 8))),
                                    true
                                    //, Encoding.UTF8.GetBytes("whatever")); // some more personalization
                                    );

            CryptoServicesRegistrar.SetSecureRandom(random);
        }

        private static void VerifyIntegrity()
        {
            var location = typeof(CryptoServicesRegistrar).Assembly.Location;
            var assemblyBytes = File.ReadAllBytes(location);

            var calc = CryptoServicesRegistrar.CreateService(FipsShs.Sha256).CreateCalculator();

            using (var digestStream = calc.Stream)
            {
                digestStream.Write(assemblyBytes, 0, assemblyBytes.Length);
                digestStream.Close();
            }

            var digest = Hex.ToHexString(calc.GetResult().Collect());
            if (digest != HEX_DIGEST_FIPS_1_0_1)
            {
                throw new ApplicationException("integrity check failed: we probably did not load correct bc-fips-1.0.1.dll").Demystify();
            }
        }
    }
}
