using System.Diagnostics;

namespace Dkbe.Certifier.Fips.Helpers
{
    /// <summary>
    /// Parses a cert out in the openssl known in Human Readable format
    /// </summary>
    internal static class CertOutParser
    {
        /// <summary>
        /// Parses a cert out in the openssl known in Human Readable format
        /// </summary>
        /// <param name="certAsPem"></param>
        /// <returns>Certificate details in Human Readable format</returns>
        public static string ParseOut(string certAsPem)
        {
            var proc = new Process()
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = "x509 -text -in -",

                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    RedirectStandardError = true,
                }
            };

            try
            {
                proc.Start();

                proc.StandardInput.Write(certAsPem);
                proc.StandardInput.Close();

                var parsed = proc.StandardOutput.ReadToEnd();
                var err = proc.StandardError.ReadToEnd();

                proc.WaitForExit(600);

                return parsed;
            }
            catch (System.Exception ex)
            {
                return "error parsing out certificate: " + ex.Message;
            }
        }
    }
}
