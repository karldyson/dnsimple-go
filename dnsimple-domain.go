// Package provides dnsimple-domain which facilitates the manipulation of domains in the registry via the DNS Simple API
package main

/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

TODO (no particular order):
* add register functionality
  * should present a list of contacts and prompt for a contact ID
  * if only one contact found, offer it as a default
  * registering a domain should pause last thing before actual registration to confirm the details on screen to the user
* add renewal functionality
  * offer the user an opportunity (cli flag?) for period to renew for, default to a year

*/

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"github.com/dnsimple/dnsimple-go/dnsimple"
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

	var period int
	flag.IntVar(&period, "period", 1, "registration or renewal period")

	var contact int
	flag.IntVar(&contact, "contact", 0, "contact id")

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
		if domain == "" {
			fmt.Printf("Listing domains in account %s:\n", config.accountNumber)
			listDomainsInAccount()
		} else {
			fmt.Printf("Listing details for domain %s:\n", domain)
			d, e := getDomainDetails(domain)
			if e != nil {
				fmt.Fprintf(os.Stderr, "Error: error fetching domain details: %s\n", e)
			}
			listDomainDetails(d)
			fmt.Println()
			fmt.Printf("Listing registrant details for domain %s:\n", domain)
			c, e := getContactDetails(d.RegistrantID)
			if e != nil {
				fmt.Fprintf(os.Stderr, "Error: error fetching contact details: %s\n", e)
			}
			listContactDetails(c)
		}
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
		fmt.Printf("%s", domain)
		switch r.Data.Premium {
		case true:
			fmt.Printf(" is a premium domain and")
		}
		switch r.Data.Available {
		case true:
			p, err := getDomainPrice(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: error checking pricing details for domain %s: %s\n", domain, err)
			}
			fmt.Printf(" is available to register at £%.2f", p.Data.RegistrationPrice)
		case false:
			fmt.Printf(" is NOT available to register")
		}
		fmt.Println()
	case "renew":
		if domain == "" {
			fmt.Fprintf(os.Stderr, "Error: a domain must be passed in\n")
			flag.Usage()
			os.Exit(1)
		}
		p, err := getDomainPrice(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: error checking pricing details for domain %s: %s\n", domain, err)
		}
		if(askUserYesNo(fmt.Sprintf("Do you wish to renew %s for 1 year for £%.2f ?", domain, p.Data.RenewalPrice))) {
			client := getApiClient()

			renewalResponse, err := client.Registrar.RenewDomain(context.Background(), config.accountNumber, domain, &dnsimple.RenewDomainInput{Period: period,})
			if(err != nil) {
				fmt.Fprintf(os.Stderr, "Error: error renewing domain: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("%d: Domain %d renewed for %d year. %s\n", renewalResponse.Data.ID, renewalResponse.Data.DomainID, renewalResponse.Data.Period, renewalResponse.Data.State)
			return
		} else {
			fmt.Println("Renewal aborted")
		}
	case "register":
		if domain == "" {
			fmt.Fprintf(os.Stderr, "Error: a domain must be passed in\n")
			flag.Usage()
			os.Exit(1)
		}
		if contact == 0 {
			if config.defaultContact != 0 {
				contact = config.defaultContact
			} else {
				fmt.Fprintf(os.Stderr, "Error: a contact ID is needed\n")
				flag.Usage()
				os.Exit(1)
			}
		}

		p, err := getDomainPrice(domain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: error checking pricing details for domain %s: %s\n", domain, err)
		}

		c, err := getContactDetails(int64(contact))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: error checking contact details %d: %s\n", contact, err)
		}
		contactName := c.FirstName + " " + c.LastName

		if(askUserYesNo(fmt.Sprintf("Do you wish to register %s to %s for %d years for £%.2f", domain, contactName, period, p.Data.RegistrationPrice))) {
			client := getApiClient()

			registrationResponse, err := client.Registrar.RegisterDomain(context.Background(), config.accountNumber, domain, &dnsimple.RegisterDomainInput{RegistrantID: contact, EnableWhoisPrivacy: false, EnableAutoRenewal: false,})
			if(err != nil) {
				fmt.Fprintf(os.Stderr, "Error: error registering domain: %s\n", err)
				os.Exit(1)
			}
			fmt.Printf("%d: Domain %d registered to %d for %d year. %s\n", registrationResponse.Data.ID, registrationResponse.Data.DomainID, registrationResponse.Data.RegistrantID, registrationResponse.Data.Period, registrationResponse.Data.State)
		}

		return
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}
