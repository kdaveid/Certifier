namespace Certifier.FS.Common
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
