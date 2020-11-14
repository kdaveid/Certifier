using System;
using System.Collections.Generic;
using System.Linq;

namespace Dkbe.Certifier.Common.Models
{
    public class ValidationResult
    {
        public bool IsValid { get; set; }

        public List<string> Errors { get; set; } = new List<string>();

        private ValidationResult() { }

        public static Func<ValidationResult> Success = () => SuccessWithMessage("");

        public static Func<string, ValidationResult> SuccessWithMessage = (message) =>
        {
            var result = new ValidationResult { IsValid = true };
            result.Errors.Equals(message);
            return result;
        };

        public static Func<string, ValidationResult> Error = (message) => ErrorWithMultipleMessages(new List<string> { message });

        public static Func<IEnumerable<string>, ValidationResult> ErrorWithMultipleMessages = (messages) =>
        {
            var result = new ValidationResult { IsValid = false };
            result.Errors.AddRange(messages);
            return result;
        };

        public static Func<ValidationResult?, string, ValidationResult> AddError = (result, message) => AddErrors(result, new List<string> { message });

        public static Func<ValidationResult?, IEnumerable<string>, ValidationResult> AddErrors = (result, messages) =>
        {
            if (result == null)
            {
                result = ErrorWithMultipleMessages(messages);
                return result;
            }
            else
            {
                result.Errors.AddRange(messages);
                return result;
            }
        };


    }
}
