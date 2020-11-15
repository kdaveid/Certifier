// Learn more about F# at http://fsharp.org
namespace Dkbe.Certifier.FS.Console

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

    

module ConsoleApp = 
    [<EntryPoint>]
    let main argv =
        let certOpts =
            {
                CommonName = "localhost"
                Country = "CH"
                ValidityPeriod = 
                {
                    StartDateUtc = DateTime.UtcNow
                    EndDateUtc = DateTime.UtcNow.AddYears(1)
                }
            }
        Console.WriteLine("{0}", certOpts.CommonName)
        0 // return an integer exit code
