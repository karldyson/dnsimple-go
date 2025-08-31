/*

Package provides dnsimple-cds which facilitates the manipulation of DS records in the registry via the DNS Simple API

Designed to be run from cron, looks at the CDS records for a zone and sync'd the DS records in the parent zone via
the DNSimple registrar API.

Can be provided with a domain on the command line, and will analyse CDS and DS record set alignment.

If the domain is not in the DNSimple account, it'll enable dry run mode because it can't actually make any changes.

If no domain is supplied, the code will cycle through all domains in the DNSimple account.

By default, it'll make changes, unless the -dryrun option is supplied.

*/

package main

/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

TODO:

* ideally modify the doQuery function in common.go to be able to optionally take a nameserver parameter and then:
* have this code look up the auth for the CDS and DS and use those for the queries instead of a validating resolver which is subject to caching

*/

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/miekg/dns"
)

var dryrun bool

// main collects the CLI flags,
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <domain>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Actions:\n")
		fmt.Fprintf(os.Stderr, "\tlist:\tlist the domains in the account\n")
		fmt.Fprintf(os.Stderr, "\tcheck:\tcheck the availability of the domain for registration\n")
		fmt.Fprintf(os.Stderr, "\tregister:\tregister the domain\n")
		fmt.Fprintf(os.Stderr, "\trenew:\trenew the domain registration\n")
		fmt.Fprintf(os.Stderr, "\n")
		flag.PrintDefaults()
	}

	flag.BoolVar(&dryrun, "dryrun", false, "dry run, just report actions")

	// parse the CLI flags
	flag.Parse()

	// set verbosity if debug is enabled
	if *debugOutput && !*verboseOutput {
		*verboseOutput = true
	}

	if *revision {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			panic("not ok reading build info!")
		}
		fmt.Printf("%s version information:\ncommit %s\n%+v\n", os.Args[0], versionString, bi)
		return
	}

	if *version {
		fmt.Printf("%s version %s\n", os.Args[0], versionString)
		return
	}

	//config = make(map[string]string)

	// variables scoped to the main function
	var (
		domain string  // the domain we're processing
		errs   []error // somewhere for errors
	)

	// do we need to collect the returned value(s) ..? parsing the config can be done in the func only...?
	_, errs = parseConfigurationFile(*configFile)
	if errs != nil {
		fmt.Fprintf(os.Stderr, "Error: Configuration error(s) while parsing config file (%s)\n%s\n", *configFile, errs)
		os.Exit(1)
	} else {
		_verbose(fmt.Sprintf("Configuration loaded from %s", *configFile))
	}

	// switch the length of the CLI arguments left after CLI flag processing
	// we're expecting <domain> and then optionally the <action> which will default to "list" and an optional <keytag>
	switch len(flag.Args()) {
	case 0:
		_debug("nothing passed, so defaulting to list")
	case 1:
		domain = flag.Args()[0]
	default:
		// and a default catching something weird
		fmt.Fprintf(os.Stderr, "Error: invalid number of CLI parameters\n")
		flag.Usage()
		os.Exit(1)
	}

	// some debug to clarify the options we are operating with...
	_debug(fmt.Sprintf("domain: %s", domain))

	if domain == "" {
		domains, e := getDomainsInAccount("")
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error: error fetching domains from API: %s", e)
			os.Exit(1)
		}
		d := make([]string, 0)
		for _, domain := range domains {
			d = append(d, domain.Name)
		}
		sort.Strings(d)
		for _, domain := range d {
			checkCDSvsDS(domain, dryrun)
		}
	} else {
		_, err := domainExistsInAccount(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s does not exist in this account (%s) - dryrun mode enabled.\n", domain, config.accountNumber)
			dryrun = true
		} else {
			_debug(fmt.Sprintf("domain %s exists in account (%s)", domain, config.accountNumber))
		}
		checkCDSvsDS(domain, dryrun)
	}
}

func checkCDSvsDS(d string, dryrun bool) error {
	fmt.Printf("== Starting domain %s at %s\n", d, time.Now().Format(time.RFC3339))

	cdsrrs, err := getCdsFromDns(d)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error retrieving CDS records for %s: %s\n", d, err)
		return err
	}
	var hasCds bool
	if len(cdsrrs) > 0 {
		tags := make([]string, 0)
		for cds := range cdsrrs {
			tags = append(tags, (fmt.Sprintf("%d/%d", cds, cdsrrs[cds].Algorithm)))
		}
		fmt.Printf("Found %d CDS record(s) : %s\n", len(cdsrrs), strings.Join(tags, ", "))
		hasCds = true
	} else {
		fmt.Printf("No CDS records for %s\n", d)
		hasCds = false
	}

	dsrrs, err := getDsFromDns(d)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error retrieving DS records for %s: %s\n", d, err)
		return err
	}
	var hasDs bool
	if len(dsrrs) > 0 {
		tags := make([]string, 0)
		for ds := range dsrrs {
			tags = append(tags, (fmt.Sprintf("%d/%d", ds, dsrrs[ds].Algorithm)))
		}
		fmt.Printf("Found %d DS record(s) .: %s\n", len(dsrrs), strings.Join(tags, ", "))
		hasDs = true
	} else {
		fmt.Printf("No DS records for %s\n", d)
		hasDs = false
	}

	if !hasCds {
		fmt.Printf("No CDS records; nothing to do.\n")
	} else if hasCds && !hasDs {
		fmt.Printf("DS needs adding\n")
		for dsTag, ds := range cdsrrs {
			fmt.Printf("Attempting addition of DS %d/%d\n", dsTag, ds.Algorithm)

			dsR, ok, _, err := dsExistsInRegistry(d, dsTag)
			if err == nil && ok {
				fmt.Printf("DS %d/%d already exists in the registry with ID %d\n", dsTag, ds.Algorithm, dsR.ID)
				continue
			} else {
				delegationSignerRecord, _ := makeDelagationSignerRecordFromCds(ds)
				if dryrun {
					fmt.Printf("= Dryrun, no alterations made\n")
				} else {
					dsResponse, err := addDelegationSignerRecordToRegistry(d, delegationSignerRecord)
					if err == nil {
						fmt.Printf("DS %d/%d created in the registry with ID %d\n", dsTag, ds.Algorithm, dsResponse.Data.ID)
					} else {
						fmt.Fprintf(os.Stderr, "Error creating DS record in the registry: %s\n", err)
					}
				}
			}
		}
	} else {
		fmt.Printf("Checking DS exists for each CDS\n")

		// look through the CDS records to see if any are missing from the DS records (and need adding)
		for cdsTag, cds := range cdsrrs {
			ds, ok := dsrrs[cdsTag]
			if ok {
				fmt.Printf("DS %d/%d exists\n", ds.KeyTag, ds.Algorithm)
			} else {
				fmt.Printf("DS %d/%d is missing and needs adding\n", cdsTag, cds.Algorithm)
				if dryrun {
					fmt.Printf("= Dryrun, no alterations made\n")
					continue
				} else {
					fmt.Printf("Attempting addition of DS %d/%d\n", cdsTag, cds.Algorithm)

					dsR, ok, dsCount, err := dsExistsInRegistry(d, cdsTag)
					if err == nil && ok {
						fmt.Printf("Error: DS %d/%d is one of %d that already exist in the registry (ID %d)\n", cdsTag, cds.Algorithm, dsCount, dsR.ID)
						continue
					} else {
						delegationSignerRecord, _ := makeDelagationSignerRecordFromCds(cds)
						client := getApiClient()
						dsResponse, err := client.Domains.CreateDelegationSignerRecord(context.Background(), config.accountNumber, d, delegationSignerRecord)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Error: error creating DS record in the registry: %s\n", err)
							continue
						}
						fmt.Printf("DS %d/%d created in the registry with ID %d\n", cdsTag, cds.Algorithm, dsResponse.Data.ID)
					}
				}
			}
		}

		fmt.Printf("Checking CDS exists for each DS\n")

		// look through the DS records to see if any are missing from the CDS records (and need removing)
		for ds := range dsrrs {
			cds, ok := cdsrrs[ds]
			if ok {
				fmt.Printf("CDS %d/%d exists\n", ds, cds.Algorithm)
			} else {
				fmt.Printf("CDS %d/%d is missing so the DS needs removing\n", ds, dsrrs[ds].Algorithm)
				if dryrun {
					fmt.Printf("Dryrun, no alterations made\n")
					continue
				} else {
					fmt.Printf("Attempting removal of DS with keytag %d\n", ds)

					dsR, ok, dsCount, err := dsExistsInRegistry(d, ds)
					if err == nil && ok {
						_verbose(fmt.Sprintf("DS %d/%d is one of %d that exist in the registry (ID %d)", ds, dsrrs[ds].Algorithm, dsCount, dsR.ID))
						client := getApiClient()
						_, err := client.Domains.DeleteDelegationSignerRecord(context.Background(), config.accountNumber, d, dsR.ID)
						if err == nil {
							fmt.Printf("DS %d/%d (ID %d) deleted\n", dsrrs[ds].KeyTag, dsrrs[ds].Algorithm, dsR.ID)
						} else {
							fmt.Fprintf(os.Stderr, "Error: error received from registrar API while deleting DS record (keytag %s, ID %d): %d\n", err, cds.KeyTag, dsR.ID)
							continue
						}
					} else {
						fmt.Fprintf(os.Stderr, "Error: DS %d/%d is not one of the %d in the registry.\n", ds, dsrrs[ds].Algorithm, dsCount)
						continue
					}
				}
			}
		}
	}
	fmt.Printf("== Finished domain %s at %s\n", d, time.Now().Format(time.RFC3339))
	return nil
}

func makeDelagationSignerRecordFromCds(cds dns.CDS) (dnsimple.DelegationSignerRecord, error) {
	var delegationSigner dnsimple.DelegationSignerRecord
	delegationSigner.Keytag = strconv.FormatUint(uint64(cds.KeyTag), 10)
	delegationSigner.Algorithm = strconv.FormatUint(uint64(cds.Algorithm), 10)
	delegationSigner.DigestType = strconv.FormatUint(uint64(cds.DigestType), 10)
	delegationSigner.Digest = cds.Digest
	return delegationSigner, nil
}

func addDelegationSignerRecordToRegistry(domain string, ds dnsimple.DelegationSignerRecord) (*dnsimple.DelegationSignerRecordResponse, error) {
	client := getApiClient()
	dsResponse, err := client.Domains.CreateDelegationSignerRecord(context.Background(), config.accountNumber, domain, ds)
	if err != nil {
		_debug(fmt.Sprintf("Error: error creating DS record in the registry: %s\n", err))
		return dsResponse, errors.New(fmt.Sprintf("%s", err))
	}
	_debug(fmt.Sprintf("DS record with keytag %d alg %d created in the registry with ID %d", ds.Keytag, ds.Algorithm, dsResponse.Data.ID))
	return dsResponse, nil
}
