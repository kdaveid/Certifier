using Dkbe.Certifier.Common.Interfaces;

namespace Dkbe.Certifier.Common.Models.Validators
{
    public class RootCertOptionsValidator : IValidator<RootCertOptions>
    {
        public ValidationResult Validate(RootCertOptions model)
        {
            ValidationResult? res = null;

            if (model.CertOptions == null || !model.CertOptions.IsValid())
            {
                ValidationResult.AddError(res, $"{nameof(model.CertOptions)} is null or invalid");
            }

            return res ?? ValidationResult.Success();
        }
    }
}
