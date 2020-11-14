using System.Collections.Generic;

namespace Dkbe.Certifier.Common.Interfaces
{
    public interface IValidation
    {
        bool IsValid();
        IEnumerable<string> ValidationErrors();
    }
}
