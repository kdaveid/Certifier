using Dkbe.Certifier.Common.Interfaces;
using Dkbe.Certifier.Common.Models.Validators;
using System;
using System.Collections.Generic;

namespace Dkbe.Certifier.Common.Models
{
    public class ValidityPeriod : IValidation
    {
        public DateTime StartDateUtc { get; }
        public DateTime EndDateUtc { get; }

        public static Func<DateTime, DateTime, ValidityPeriod> CreateValidityPeriod = (StartDateUtc, EndDateUtc) => new ValidityPeriod(StartDateUtc, StartDateUtc);
        public static Func<ValidityPeriod> CreateDefaultValidityPeriod = () => new ValidityPeriod(DateTime.UtcNow, DateTime.UtcNow.AddYears(1));

        private ValidityPeriod(DateTime startDateUtc, DateTime endDateUtc)
        {
            StartDateUtc = startDateUtc;
            EndDateUtc = endDateUtc;
        }

        public bool IsValid() => new ValidityPeriodValidator().Validate(this).IsValid;

        public IEnumerable<string> ValidationErrors() => new ValidityPeriodValidator().Validate(this).Errors;
    }
}
