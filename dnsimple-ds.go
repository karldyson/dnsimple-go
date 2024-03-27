// Package provides dnsimple-ds which facilitates the manipulation of DS records in the registry via the DNS Simple API
package main

/*

TODO (no particular order):
* Add some annotation and/or docs
* Add a readme
* We should check that the domain is in the account before proceeding, rather than waiting for an error later
* do we need to return / make cp object in main() ? all config set up & catching is done in the config parsing func
* getApiClient feels a bit light on error catching and handling...
* getDnskeyFromDns feels like its duplicating a lot of the RCODE checking from doQuery...?
  double check, but mindful of whether everything expects an answer as opposed to delegation etc?
* getDnskeyFromDns should probably return a map of resource records instead of that faff...?

*/

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/miekg/dns"
)

// main collects the CLI flags,
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <domain> [action] [keytag]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Actions:\n")
		fmt.Fprintf(os.Stderr, "\tlist, listds:\tlist the DS records in the registry\n\tlistkeys:\tlist the DNSKEY records in DNS\n\tlistall:\tlist everything\n")
		fmt.Fprintf(os.Stderr, "\tadd:\t\tadd the supplied keytag, or, if no keytag is supplied, lists the DNSKEY records in DNS\n")
		fmt.Fprintf(os.Stderr, "\tdelete:\t\tdelete the supplied keytag, or, if no keytag is supplied, lists the DS records in the registry\n")
		fmt.Fprintf(os.Stderr, "\n")
		flag.PrintDefaults()
	}

	// parse the CLI flags
	flag.Parse()

	// set verbosity if debug is enabled
	if *debugOutput && !*verbose {
		*verbose = true
	}

	if *version {
		//		goVer := runtime.Version
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			panic("not ok!")
		}
		fmt.Printf("%s version information:\n%+v\n", os.Args[0], bi)
		return
	}

	config = make(map[string]string)

	// variables scoped to the main function
	var (
		domain string           // the domain we're processing
		action string  = "list" // the action we're taking
		keytag uint16           // the keytag we're processing
		errs   []error          // somewhere for errors
	)

	// do we need to collect the returned value(s) ..? parsing the config can be done in the func only...?
	cp, errs = parseConfigurationFile(*configFile)
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
		fmt.Fprintf(os.Stderr, "Error: no domain supplied\n")
		flag.Usage()
		os.Exit(1)
	case 1:
		domain = flag.Args()[0]
	case 2:
		domain = flag.Args()[0]
		action = flag.Args()[1]
	case 3:
		domain = flag.Args()[0]
		action = flag.Args()[1]
		// we parse the keytag into a 16 bit unsigned integer to allow us to catch if it's not 0-65535
		kt, err := strconv.ParseUint(flag.Args()[2], 10, 16)
		if err == nil {
			keytag = uint16(kt) // parsing it above gives us a uint64 and we want uint16
		} else {
			// so error and exit if it's not valid
			fmt.Fprintf(os.Stderr, "Error: %s is not a valid keytag. Expected an integer in the range 1-65535\n", flag.Args()[2])
			_debug(fmt.Sprintf("Error: Parsing the keytag into an unsigned integer resulted in error: %s\n", err))
			os.Exit(1)
		}
		// we need to catch it being 0, so belt and braces while we're here...
		if keytag <= 0 || keytag > 65535 {
			fmt.Fprintf(os.Stderr, "Error: keytag %d is out of valid range. Expected an integer in the range 1-65535\n", keytag)
			os.Exit(1)
		}
	default:
		// and a default catching something weird
		fmt.Fprintf(os.Stderr, "Error: invalid number of CLI parameters\n")
		flag.Usage()
		os.Exit(1)
	}

	// some debug to clarify the options we are operating with...
	_debug(fmt.Sprintf("domain: %s, action: %s, keytag: %d", domain, action, keytag))

	// work out what action we're performing
	switch action {
	case "list", "listds":
		fmt.Printf("Listing DS records in the registry for domain %s\n", domain)
		listDsInRegistry(domain)
	case "listkeys":
		fmt.Printf("Listing DNSKEY records in DNS for domain %s\n", domain)
		listDnskeyInDns(domain)
	case "listall":
		fmt.Printf("Listing DS records in the registry for domain %s\n", domain)
		listDsInRegistry(domain)
		fmt.Printf("Listing DNSKEY records in DNS for domain %s\n", domain)
		listDnskeyInDns(domain)
	case "add":
		if keytag <= 0 {
			fmt.Printf("Warning: no keytag was supplied for addition, listing DNSKEY records found in DNS for domain %s\n", domain)
			listDnskeyInDns(domain)
		} else {
			_, err, ok := dsExistsInRegistry(domain, keytag)
			if err == nil && ok {
				fmt.Fprintf(os.Stderr, "Error: DS record with keytag %d already exists in the registry in domain %s\n", keytag, domain)
				os.Exit(1)
			}
			_verbose(fmt.Sprintf("Checking DNS for existence of DNSKEY with keytag %d in domain %s\n", keytag, domain))
			dnskeyRr, err := dnskeyExistsInDns(domain, keytag)
			if err == nil {
				_verbose(fmt.Sprintf("DNSKEY with keytag %d exists in DNS in %s\n", keytag, domain))

				// ask the user if they really want to, if it's a ZSK
				if dnskeyRr.Flags == 256 {
					if !askUserYesNo(fmt.Sprintf("The DNSKEY with keytag %d is a ZSK, are you sure you want to proceed?", keytag)) {
						fmt.Printf("Operation aborted\n")
						return
					}
				}

				// validate that the keyset is signed with the DNSKEY requested
				// if it is NOT signed with this key, but is the same algorithm as the existing DS record(s), adding will NOT cause issues

				// we've done all the checks, create and add the DS
				digestType, err := strconv.ParseUint(config["dsDigestType"], 10, 8)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: error converting string digest type (%s) to integer value\n", config["dsDigestType"])
					_debug(fmt.Sprintf("Error: converting the digest type (%s) to an integer resulted in error: %s\n", config["dsDigestType"], err))
					os.Exit(1)
				}
				_verbose(fmt.Sprintf("Creating DS record witih digest type %s from DNSKEY record\n", dns.HashToString[uint8(digestType)]))
				dsRr := dnskeyRr.ToDS(uint8(digestType))
				_debug(fmt.Sprintf("DS record created: DS %d %d %d %s\n", dsRr.KeyTag, dsRr.Algorithm, dsRr.DigestType, dsRr.Digest))

				var delegationSigner dnsimple.DelegationSignerRecord
				delegationSigner.Keytag = strconv.FormatUint(uint64(dsRr.KeyTag), 10)
				delegationSigner.Algorithm = strconv.FormatUint(uint64(dsRr.Algorithm), 10)
				delegationSigner.DigestType = strconv.FormatUint(uint64(dsRr.DigestType), 10)
				delegationSigner.Digest = dsRr.Digest
				client := getApiClient()
				dsResponse, err := client.Domains.CreateDelegationSignerRecord(context.Background(), config["accountNumber"], domain, delegationSigner)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: error creating DS record in the registry: %s\n", err)
					os.Exit(1)
				}
				fmt.Printf("DS record with keytag %d created in domain %s in the registry with ID %d\n", keytag, domain, dsResponse.Data.ID)
				fmt.Println("Note that it may take some time for the DS record to appear in DNS.")
				return
			} else {
				fmt.Fprintf(os.Stderr, "Error: DNSKEY with keytag %d does not exist in DNS in domain %s\n", keytag, domain)
				os.Exit(1)
			}
		}
	case "delete":
		if keytag <= 0 {
			fmt.Printf("Warning: no keytag was supplied for deletion, listing DS records found in the registry for domain %s\n", domain)
			listDsInRegistry(domain)
		} else {
			_verbose(fmt.Sprintf("Checking registry for existence of DS record with keytag %d in domain %s\n", keytag, domain))
			dsR, err, ok := dsExistsInRegistry(domain, keytag)
			if err == nil && ok {
				_verbose(fmt.Sprintf("DS record with keytag %d exists in domain %s in the registry\n", keytag, domain))

				// delete the DS
				client := getApiClient()
				_, err := client.Domains.DeleteDelegationSignerRecord(context.Background(), config["accountNumber"], domain, dsR.ID)
				if err == nil {
					fmt.Printf("DS record with keytag %d and ID %d in domain %s deleted", keytag, dsR.ID, domain)
				} else {
					fmt.Fprintf(os.Stderr, "Error: error received from registrar API while deleting DS record (keytag %s, ID %d): %s\n", err, keytag, dsR.ID)
					os.Exit(1)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Error: DS record with keytag %d cannot be found in domain %s in the registry\n", keytag, domain)
				os.Exit(1)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}
