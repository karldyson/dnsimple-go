// Package provides dnsimple-ns which facilitates the manipulation of delegation nameservers in the registry via the DNS Simple API
package main

/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

TODO (no particular order):
* wait for functionality to alter glue and/or nameserver sets and/or delegation details

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
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <domain> [action]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Actions:\n")
		fmt.Fprintf(os.Stderr, "\tlist:\tlist the delegation NS records in the registry\n")
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
		fmt.Fprintf(os.Stderr, "Error: no domain supplied\n")
		flag.Usage()
		os.Exit(1)
	case 1:
		domain = flag.Args()[0]
	case 2:
		domain = flag.Args()[0]
		action = flag.Args()[1]
	default:
		// and a default catching something weird
		fmt.Fprintf(os.Stderr, "Error: invalid number of CLI parameters\n")
		flag.Usage()
		os.Exit(1)
	}

	// some debug to clarify the options we are operating with...
	_debug(fmt.Sprintf("domain: %s, action: %s\n", domain, action))

	// check the domain is in the account first
	_, err := domainExistsInAccount(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: domain %s does not exist in this account (%s)\n", domain, config.accountNumber)
		os.Exit(1)
	} else {
		_debug(fmt.Sprintf("domain %s exists in account (%s)", domain, config.accountNumber))
	}

	switch action {
	case "list":
		fmt.Printf("Listing NS records in the registry for domain %s\n", domain)
		listNsInRegistry(domain)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}
