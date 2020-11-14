using Dkbe.Certifier.Common.Interfaces;

namespace Dkbe.Certifier.Common.Models.Validators
{
    public class CertOptionsValidator : IValidator<CertOptions>
    {
        public ValidationResult Validate(CertOptions model)
        {
            ValidationResult? res = null;

            if (!model.ValidityPeriod.IsValid())
            {
                ValidationResult.AddErrors(res, model.ValidityPeriod.ValidationErrors());
            }

            if (string.IsNullOrWhiteSpace(model.CommonName))
            {
                ValidationResult.AddError(res, nameof(model.CommonName));
            }

            return res ?? ValidationResult.Success();
        }
    }
}
