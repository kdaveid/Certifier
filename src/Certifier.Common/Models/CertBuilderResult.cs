using System;

namespace Dkbe.Certifier.Common.Models
{
    public class CertBuilderResult
    {
        /// <summary>
        /// Cert in PEM format as byte[]
        /// </summary>
        public byte[] SignedCertBytes { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Cert in PEM format as string
        /// </summary>
        public string SignedCertAsPem { get; set; } = "";

        public string CommonName { get; set; } = "";

        public string Subject { get; set; } = "";

        public string HumanReadableCertString { get; set; } = "";

        public long SerialNumber { get; set; }

        public string Thumbprint { get; set; } = "";

        public string ThumbprintMS { get; set; } = "";

        public DateTime NotBefore { get; set; }

        public DateTime NotAfter { get; set; }

        public byte[] IssuerCertBytes { get; set; } = Array.Empty<byte>();
    }
}
