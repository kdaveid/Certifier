using Dkbe.Certifier.Common.Interfaces;
using Dkbe.Certifier.Common.Models.Validators;
using System;
using System.Collections.Generic;

namespace Dkbe.Certifier.Common.Models
{
    public class CertOptions : IValidation
    {
        public string CommonName { get; protected set; }
        public string Country { get; protected set; }
        public string Organization { get; protected set; }
        public string OrganizationUnit { get; protected set; }

        public IEnumerable<string> SubjectAlternativeNames { get; protected set; }
        public bool ServerAuthentication { get; protected set; }

        public ValidityPeriod ValidityPeriod { get; protected set; }

        private CertOptions(
            Func<ValidityPeriod> validityPeriod,
            string commonName = "",
            string country = "",
            string organization = "",
            string orgUnit = "",
            bool? serverAuthentication = false,
            List<string>? san = default)
        {
            ValidityPeriod = validityPeriod();

            CommonName = commonName;
            Country = country;
            Organization = organization;
            OrganizationUnit = orgUnit;

            ServerAuthentication = serverAuthentication ?? false;
            SubjectAlternativeNames = san ?? new List<string>();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ValidityPeriod">Function</param>
        /// <param name="CommonName">Common name of certificate</param>
        public static Func<Func<ValidityPeriod>, string, string, string, string, bool?, List<string>?, CertOptions> CreateCertificateOptions = 
            (ValidityPeriod, CommonName, Country, Organization, OrganizationUnit, ServerAuthentication, SubjectAlternativeNames) =>
            {
                return new CertOptions(ValidityPeriod, CommonName, Country, Organization, OrganizationUnit, ServerAuthentication, SubjectAlternativeNames);
            };

        //public static CertOptions NewClientCert(
        //    string commonName,
        //    string country,
        //    string organization,
        //    string orgUnit,
        //    DateTime startDateUtc = default,
        //    DateTime endDateUtc = default) => new CertOptions(
        //        commonName,
        //        country,
        //        organization,
        //        orgUnit,
        //        null,
        //        null,
        //        startDateUtc,
        //        endDateUtc);

        //public static CertOptions NewServerCert(
        //    string commonName,
        //    string country,
        //    string organization,
        //    string orgUnit,
        //    List<string>? san = default,
        //    DateTime startDateUtc = default,
        //    DateTime endDateUtc = default) => new CertOptions(
        //        commonName,
        //        country,
        //        organization,
        //        orgUnit,
        //        true,
        //        san,
        //        startDateUtc,
        //        endDateUtc);

        //public static CertOptions NewRootCaCert(
        //    string commonName,
        //    string country,
        //    string organization,
        //    string orgUnit,
        //    DateTime startDateUtc = default,
        //    DateTime endDateUtc = default) => new CertOptions(
        //        commonName,
        //        country,
        //        organization,
        //        orgUnit,
        //        false,
        //        null,
        //        startDateUtc,
        //        endDateUtc);




        public bool IsValid() => new CertOptionsValidator().Validate(this).IsValid;

        public IEnumerable<string> ValidationErrors() => new CertOptionsValidator().Validate(this).Errors;
    }
}
