// Package provides dnsimple-domain which facilitates the manipulation of domains in the registry via the DNS Simple API
package main

/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

TODO (no particular order):
* add register functionality
* add renewal functionality

*/

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
)

// main collects the CLI flags,
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [action] <domain>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Actions:\n")
		fmt.Fprintf(os.Stderr, "\tlist:\tlist the domains in the account\n")
		fmt.Fprintf(os.Stderr, "\tcheck:\tcheck the availability of the domain for registration\n")
		fmt.Fprintf(os.Stderr, "\tregister:\tregister the domain\n")
		fmt.Fprintf(os.Stderr, "\trenew:\trenew the domain registration\n")
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
		domain string           // the domain we're processing
		action string  = "list" // the action we're taking
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
		_debug("nothing passed, so defaulting to list")
	case 1:
		action = flag.Args()[0]
	case 2:
		action = flag.Args()[0]
		domain = flag.Args()[1]
	default:
		// and a default catching something weird
		fmt.Fprintf(os.Stderr, "Error: invalid number of CLI parameters\n")
		flag.Usage()
		os.Exit(1)
	}

	// some debug to clarify the options we are operating with...
	_debug(fmt.Sprintf("domain: %s, action: %s", domain, action))

	switch action {
	case "list":
		fmt.Printf("Listing domains in account %s:\n", config.accountNumber)
		listDomainsInAccount()
	case "check":
		if domain == "" {
			fmt.Fprintf(os.Stderr, "Error: a domain must be passed in\n")
			flag.Usage()
			os.Exit(1)
		}
		r, err := checkDomainStatus(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: error checking status of domain %s: %s\n", domain, err)
		}
		switch r.Data.Available {
		case true:
			p, err := getDomainPrice(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: error checking pricing details for domain %s: %s\n", domain, err)
			}
			fmt.Printf("%s is available to register at £%.2f", domain, p.Data.RegistrationPrice)
		case false:
			fmt.Printf("%s is NOT available to register", domain)
		}
		switch r.Data.Premium {
		case true:
			fmt.Printf(" (and is a premium domain)")
		}
		fmt.Println()
	case "register", "renew":
		fmt.Println("action not yet implemented")
		return
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}
