// Package provides dnsimple-contact which facilitates the manipulation of contacts in the registry via the DNS Simple API
package main

/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

TODO (no particular order):
* Add creation
* Add deletion

*/

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
)

// main collects the CLI flags,
func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [action] <domain>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Actions:\n")
		fmt.Fprintf(os.Stderr, "\tlist:\tlist the contacts in the account\n")
		fmt.Fprintf(os.Stderr, "\tcreate:\tcreate a contact\n")
		fmt.Fprintf(os.Stderr, "\tdelete:\tdelete a contact\n")
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

	// variables scoped to the main function
	var (
		contact string           // the contact we're processing
		action  string  = "list" // the action we're taking
		errs    []error          // somewhere for errors
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
		contact = flag.Args()[1]
	default:
		// and a default catching something weird
		fmt.Fprintf(os.Stderr, "Error: invalid number of CLI parameters\n")
		flag.Usage()
		os.Exit(1)
	}

	// some debug to clarify the options we are operating with...
	_debug(fmt.Sprintf("contact: %s, action: %s", contact, action))

	switch action {
	case "list":
		if contact == "" {
			fmt.Printf("Listing contacts in account %s:\n", config.accountNumber)
			listContactsInAccount()
		} else {
			fmt.Printf("Listing details for contact %s:\n", contact)
			contactInt, err := strconv.ParseInt(contact, 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: error parsing string to integer: %s\n", err)
				os.Exit(1)
			}
			c, e := getContactDetails(contactInt)
			if e != nil {
				fmt.Fprintf(os.Stderr, "Error: error fetching contact details: %s\n", e)
			}
			listContactDetails(c)
		}
	case "create", "delete":
		fmt.Println("action not yet implemented")
		return
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}
