namespace Certifier.FS.Common.Models
open System

type ValidityPeriod = 
    {
        StartDateUtc : DateTime
        EndDateUtc : DateTime
    }

type CertOptions = 
    { 
        ValidityPeriod : ValidityPeriod
        CommonName : string
        Country : string 
    }

type RootCertOptions =
    {
        CertOptions : CertOptions
        Generation : int
        CrlUrls : string[]
    }