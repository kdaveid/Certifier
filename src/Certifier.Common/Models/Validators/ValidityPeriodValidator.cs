using Dkbe.Certifier.Common.Interfaces;
using System;

namespace Dkbe.Certifier.Common.Models.Validators
{
    public class ValidityPeriodValidator : IValidator<ValidityPeriod>
    {
        public ValidationResult Validate(ValidityPeriod model)
        {
            if (model.StartDateUtc.Kind != DateTimeKind.Utc)
            {
                return ValidationResult.Error(nameof(model.StartDateUtc) + " must be of kind utc");
            }
            if (model.EndDateUtc.Kind != DateTimeKind.Utc)
            {
                return ValidationResult.Error(nameof(model.EndDateUtc) + " must be of kind utc");
            }
            if (model.StartDateUtc > model.EndDateUtc)
            {
                return ValidationResult.Error(nameof(model.StartDateUtc) + " must not be before " + nameof(model.EndDateUtc));
            }

            return ValidationResult.Success();
        }
    }
}
