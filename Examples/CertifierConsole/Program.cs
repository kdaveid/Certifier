using Dkbe.Certifier.Common.Models;
using System;

namespace Dkbe.Certifier.CertifierConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            var cert = new Certifier().CreateSelfSignedCertificate("test");

        }
    }
}
