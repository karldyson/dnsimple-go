// Package provides dnsimple-ds which facilitates the manipulation of DS records in the registry via the DNS Simple API
package main

/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

TODO (no particular order):
* Add some annotation and/or docs
* Add a license, copyright, etc
* getApiClient feels a bit light on error catching and handling...
* getDnskeyFromDns feels like its duplicating a lot of the RCODE checking from doQuery...?
  double check, but mindful of whether everything expects an answer as opposed to delegation etc?
* still feels like we're a bit muddy on the difference between verbose and debug output...
* methods should mostly return errors rather than exiting... main() may want the option to handle it and carry on regardless

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
	if *debugOutput && !*verboseOutput {
		*verboseOutput = true
	}

	if *revision {
		bi, ok := debug.ReadBuildInfo()
		if !ok {
			panic("not ok reading build info!")
		}
		fmt.Printf("%s version information:\ncommit: %s\n%+v\n", os.Args[0], versionString, bi)
		return
	}

	if *version {
		fmt.Printf("%s version %s\n", os.Args[0], versionString)
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
			_debug(fmt.Sprintf("Error: Parsing the keytag into an unsigned integer resulted in error: %s", err))
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

	// check the domain is in the account first
	_, err := domainExistsInAccount(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: domain %s does not exist in this account (%s)\n", domain, config["accountNumber"])
		os.Exit(1)
	} else {
		_debug(fmt.Sprintf("domain %s exists in account (%s)", domain, config["accountNumber"]))
	}

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
		fmt.Printf("\nListing DNSKEY records in DNS for domain %s\n", domain)
		listDnskeyInDns(domain)
	case "add":
		if keytag <= 0 {
			fmt.Printf("Warning: no keytag was supplied for addition, listing DNSKEY records found in DNS for domain %s\n", domain)
			listDnskeyInDns(domain)
		} else {
			_, ok, _, err := dsExistsInRegistry(domain, keytag)
			if err == nil && ok {
				fmt.Fprintf(os.Stderr, "Error: DS record with keytag %d already exists in the registry in domain %s\n", keytag, domain)
				os.Exit(1)
			}
			_verbose(fmt.Sprintf("Checking DNS for existence of DNSKEY with keytag %d in domain %s", keytag, domain))
			dnskeyRr, err := dnskeyExistsInDns(domain, keytag)
			if err == nil {
				_verbose(fmt.Sprintf("DNSKEY with keytag %d exists in DNS in %s", keytag, domain))

				// validate that the keyset is signed with the DNSKEY requested
				// if it is NOT signed with this key, but is the same algorithm as the existing DS record(s), adding will NOT cause issues
				keyset, err := doQuery(domain, dns.TypeDNSKEY)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: cannot retrieve keyset for domain %s: %s\n", domain, err)
					os.Exit(1)
				}

				var keysetSignedWithRequestedKey bool = false
				keyAlgs := make(map[uint8]uint8)
				for _, ans := range keyset.Answer {
					switch rr := ans.(type) {
					case *dns.RRSIG:
						_debug(fmt.Sprintf("got RRSIG with keytag %d and algorithm %d", rr.KeyTag, rr.Algorithm))
						keyAlgs[rr.Algorithm]++
						if keytag == rr.KeyTag {
							keysetSignedWithRequestedKey = true
						}
					}
				}
				var warnings []string
				if keysetSignedWithRequestedKey {
					_verbose(fmt.Sprintf("The DNSKEY keyset in domain %s is signed with keytag %d", domain, keytag))
				} else {
					_debug(fmt.Sprintf("Warning: the DNSKEY keyset in domain %s is NOT signed with keytag %d", domain, keytag))
					warnings = append(warnings, fmt.Sprintf("The DNSKEY record set is not signed with the DNSKEY with keytag %d", keytag))
					existingDsSet, err := getDsFromRegistry(domain)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error: failed to fetch existing DS records from registry for domain %s: %s\n", domain, err)
						os.Exit(1)
					}
					for _, ds := range existingDsSet.Data {
						dsA, err := strconv.ParseUint(ds.Algorithm, 10, 8)
						if err != nil {
							fmt.Fprintf(os.Stderr, "Error: error converting string to integer: %s\n", err)
							os.Exit(1)
						}
						dsAlg := uint8(dsA)
						if keyAlgs[dsAlg] > 0 {
							_debug(fmt.Sprintf("Requested addition (%d) matches algorithm of existing DS record(s) (%d)", dnskeyRr.Algorithm, keyAlgs))
							if len(warnings) > 0 {
								warnings[0] = fmt.Sprintf("%s\n     (although it's of the same algorithm as existing DS records, so may be ok if you're pre-publishing)", warnings[0])
							}
						} else {
							_debug(fmt.Sprintf("Warning: algorithm of requested DS addition (%d) does NOT match the algorithm of an existing DS record(s) (%d)", dnskeyRr.Algorithm, keyAlgs))
							warnings = append(warnings, fmt.Sprintf("The DNSKEY with keytag %d does NOT match algorithm of existing DS record(s)", keytag))
						}
					}
				}

				// add a warning if it's a ZSK
				if dnskeyRr.Flags == 256 {
					_debug(fmt.Sprintf("Warning: the DNSKEY with keytag %d is a ZSK (%d)", keytag, dnskeyRr.Flags))
					warnings = append(warnings, fmt.Sprintf("The DNSKEY with keytag %d is a ZSK", keytag))
				}

				switch len(warnings) {
				case 0:
					_debug("There are no warnings")
				case 1:
					fmt.Printf("There is a warning for this addition:\n")
					fmt.Printf("  => %s\n", warnings[0])
				default:
					fmt.Printf("There are %d warnings for this addition:\n", len(warnings))
					for _, w := range warnings {
						fmt.Printf("  => %s\n", w)
					}
				}

				if len(warnings) > 0 {
					if *forceOperation {
						_debug("there are warnings, but the -force flag overrides")
					} else if !askUserYesNo("Given the warnings, do you want to proceed?") {
						fmt.Println("Operation aborted")
						return
					}
				}

				// we've done all the checks, create and add the DS
				digestType, err := strconv.ParseUint(config["dsDigestType"], 10, 8)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: error converting string digest type (%s) to integer value\n", config["dsDigestType"])
					_debug(fmt.Sprintf("Error: converting the digest type (%s) to an integer resulted in error: %s", config["dsDigestType"], err))
					os.Exit(1)
				}
				_verbose(fmt.Sprintf("Creating DS record witih digest type %s from DNSKEY record", dns.HashToString[uint8(digestType)]))
				dsRr := dnskeyRr.ToDS(uint8(digestType))
				_debug(fmt.Sprintf("DS record created: DS %d %d %d %s", dsRr.KeyTag, dsRr.Algorithm, dsRr.DigestType, dsRr.Digest))

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
			_verbose(fmt.Sprintf("Checking registry for existence of DS record with keytag %d in domain %s", keytag, domain))
			dsR, ok, dsCount, err := dsExistsInRegistry(domain, keytag)
			if err == nil && ok {
				_verbose(fmt.Sprintf("DS record with keytag %d is one of %d that exist in domain %s in the registry", keytag, dsCount, domain))

				if dsCount == 1 {
					if *forceOperation {
						_debug("this is the ONLY DS record but the -force flag overrides")
					} else if !askUserYesNo("Are you sure you want to delete the ONLY DS record?") {
						fmt.Println("Operation aborted")
						return
					}
				}

				// delete the DS
				client := getApiClient()
				_, err := client.Domains.DeleteDelegationSignerRecord(context.Background(), config["accountNumber"], domain, dsR.ID)
				if err == nil {
					fmt.Printf("DS record with keytag %d and ID %d in domain %s deleted", keytag, dsR.ID, domain)
				} else {
					fmt.Fprintf(os.Stderr, "Error: error received from registrar API while deleting DS record (keytag %s, ID %d): %d\n", err, keytag, dsR.ID)
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
