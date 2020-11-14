using Dkbe.Certifier.Common.Interfaces;
using Dkbe.Certifier.Common.Models.Validators;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Dkbe.Certifier.Common.Models
{
    public class RootCertOptions : IValidation
    {
        public int Generation { get; } = 1;
        public IReadOnlyList<string> CrlUrls { get; } = ImmutableList.Create<string>();
        public CertOptions CertOptions { get; }


        public RootCertOptions(CertOptions certOptions, int generation, IEnumerable<string> crlUrls)
        {
            CertOptions = certOptions;
            Generation = generation;
            CrlUrls = ImmutableList.CreateRange(crlUrls ?? new string[] { });
        }

        public static Func<Func<CertOptions>, int, IEnumerable<string>, RootCertOptions> CreateRootCertOptions =
            (CertOptions, Generation, CrlUrls) => new RootCertOptions(CertOptions(), Generation, CrlUrls);

        public bool IsValid() => new RootCertOptionsValidator().Validate(this).IsValid;

        public IEnumerable<string> ValidationErrors() => new RootCertOptionsValidator().Validate(this).Errors;
    }
}
