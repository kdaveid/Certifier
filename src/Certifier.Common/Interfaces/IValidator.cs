using Dkbe.Certifier.Common.Models;

namespace Dkbe.Certifier.Common.Interfaces
{
    internal interface IValidator<T>
    {
        ValidationResult Validate(T model);
    }
}
