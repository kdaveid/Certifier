using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace Dkbe.Certifier.Fips.Extensions
{
    public static class StringExtensions
    {
        public static string UrlSafe(this string input)
        {
            char repl = '_';

            var rest = input.Replace(' ', repl)
                            .Replace('[', repl)
                            .Replace("]", "");

            return Regex.Replace(rest, @"[^0-9a-zA-Z]+", repl.ToString());
        }

        public static string GetFileNameFromUrl(string url)
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var res))
            {
                return res.Segments.Last();
            }

            throw new UriFormatException($"could not retrieve file name from {url}");
        }
    }
}
