package main

/*

TODO (no particular order):
* Add some annotation and/or docs
* Add a readme
* do we need to return / make cp object in main() ? all config set up & catching is done in the config parsing func
* getApiClient feels a bit light on error catching and handling...
* getDnskeyFromDns feels like its duplicating a lot of the RCODE checking from doQuery...?
  double check, but mindful of whether everything expects an answer as opposed to delegation etc?
* getDnskeyFromDns should probably return a map of resource records instead of that faff...?

*/

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"

	"github.com/bigkevmcd/go-configparser"
	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/miekg/dns"
)

var (
	configFile = flag.String("config", "/usr/local/etc/dnsimple.cfg", "configuration file")
	debug      = flag.Bool("debug", false, "enable debug output")
	verbose    = flag.Bool("verbose", false, "verbose output")
	config     map[string]string
	cp         *configparser.ConfigParser
	tc         *http.Client
	apiClient  *dnsimple.Client
)

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

	flag.Parse()

	if *debug && !*verbose {
		*verbose = true
	}

	config = make(map[string]string)

	var (
		domain string
		action string = "list"
		keytag uint16
		errs   []error
	)

	// do we need to collect the returned value(s) ..? parsing the config can be done in the func only...?
	cp, errs = parseConfigurationFile(*configFile)
	if errs != nil {
		fmt.Fprintf(os.Stderr, "Configuration error(s) while parsing config file (%s)\n%s\n", *configFile, errs)
		os.Exit(1)
	} else {
		_verbose(fmt.Sprintf("Configuration loaded from %s", *configFile))
	}

	switch len(flag.Args()) {
	case 1:
		domain = flag.Args()[0]
	case 2:
		domain = flag.Args()[0]
		action = flag.Args()[1]
	case 3:
		domain = flag.Args()[0]
		action = flag.Args()[1]
		kt, err := strconv.ParseUint(flag.Args()[2], 10, 16)
		if err == nil {
			keytag = uint16(kt)
		} else {
			fmt.Fprintf(os.Stderr, "Fatal: %s is not a valid keytag: %s\n", flag.Args()[2], err)
			os.Exit(1)
		}
		if keytag <= 0 || keytag > 65535 {
			fmt.Fprintf(os.Stderr, "Fatal: keytag %d is out of valid range\n", keytag)
		}
	default:
		fmt.Fprintf(os.Stderr, "Error: no domain supplied\n")
		flag.Usage()
		os.Exit(1)
	}

	_debug(fmt.Sprintf("domain: %s, action: %s, keytag: %d", domain, action, keytag))

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
			fmt.Printf("no keytag was supplied for addition, listing DNSKEY records found in DNS for domain %s\n", domain)
			listDnskeyInDns(domain)
		} else {
			fmt.Printf("checking DNS for existence of DNSKEY with keytag %d in domain %s\n", keytag, domain)
			if dnskeyExistsInDns(domain, keytag) {
				fmt.Printf("DNSKEY with keytag %d exists in DNS in %s\n", keytag, domain)
			} else {
				fmt.Fprintf(os.Stderr, "DNSKEY with keytag %d does not exist in DNS in %s\n", keytag, domain)
				os.Exit(1)
			}
		}
	case "delete":
		if keytag <= 0 {
			fmt.Printf("no keytag was supplied for deletion, listing DS records found in the registry for domain %s\n", domain)
			listDsInRegistry(domain)
		} else {
			fmt.Printf("checking registry for existence of DS record with keytag %d in domain %s\n", keytag, domain)
			if dsExistsInRegistry(domain, keytag) {
				fmt.Printf("DS record with keytag %d exists in domain %s in the registry\n", keytag, domain)
			} else {
				fmt.Fprintf(os.Stderr, "a DS record with keytag %d cannot be found in domain %s in the registry\n", keytag, domain)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown action: %s\n", action)
		flag.Usage()
		os.Exit(1)
	}
}

func doQuery(qname string, qtype uint16) (*dns.Msg, error) {

	nameserverAddr := config["nameserverAddr"]
	nameserverPort := config["nameserverPort"]

	_debug(fmt.Sprintf("qname is %s, qtype is %s", qname, dns.TypeToString[qtype]))

	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // do DNSKEY (set DO, as we want AD)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	r, rtt, err := c.Exchange(m, net.JoinHostPort(nameserverAddr, nameserverPort))
	_verbose(fmt.Sprintf("Response received from %s:%s in %s\n", nameserverAddr, nameserverPort, rtt))
	if err != nil {
		_debug(fmt.Sprintf("Query for %s/%s resulted in error: %s", qname, dns.TypeToString[qtype], err))
		return nil, err
	}
	if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
		_debug(fmt.Sprintf("Query for %s/%s resulted in rcode %s", qname, dns.TypeToString[qtype], dns.RcodeToString[r.Rcode]))
		return r, err
	}
	return nil, errors.New("wibble")
}

// feels like there's not a lot of error catching/handling going on here...
func getApiClient() *dnsimple.Client {
	if tc == nil {
		_debug("token client does not exist, so creating it")
		tc = dnsimple.StaticTokenHTTPClient(context.Background(), config["apiKey"])
	}
	if apiClient == nil {
		_debug("api client doesn't exist, so creating it")
		apiClient = dnsimple.NewClient(tc)
	}
	if apiClient != nil && config["apiEndpoint"] != "" {
		_debug(fmt.Sprintf("setting API endpoint to %s", config["apiEndpoint"]))
		//		apiClient.BaseURL = "https://api.sandbox.dnsimple.com"
		apiClient.BaseURL = config["apiEndpoint"]
	}
	return apiClient
}

func getDsFromRegistry(domain string) (*dnsimple.DelegationSignerRecordsResponse, error) {
	client := getApiClient()
	dsResponse, err := client.Domains.ListDelegationSignerRecords(context.Background(), config["accountNumber"], domain, nil)
	if err != nil {
		errorString := fmt.Sprintf("Error fetching DS records from registry for domain %s: %s\n", domain, err)
		return nil, errors.New(errorString)
	}
	return dsResponse, nil
}

func listDsInRegistry(domain string) {
	dsRecords, err := getDsFromRegistry(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching DS records from the registry: %s\n", err)
		os.Exit(1)
	}
	switch len(dsRecords.Data) {
	case 1:
		fmt.Printf("There is %d DS record\n", len(dsRecords.Data))
	default:
		fmt.Printf("There are %d DS records\n", len(dsRecords.Data))
	}
	for _, ds := range dsRecords.Data {
		fmt.Printf("  => DS %s %s %s %s\n", ds.Keytag, ds.Algorithm, ds.DigestType, ds.Digest)
	}
}

func dsExistsInRegistry(domain string, keytag uint16) bool {
	dsRecords, err := getDsFromRegistry(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving list of keys for %s: %s\n", domain, err)
		return false
	} else {
		for _, ds := range dsRecords.Data {
			_debug(fmt.Sprintf("got ds with keytag %s", ds.Keytag))
			dsKeytag, err := strconv.ParseUint(ds.Keytag, 10, 16)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fatal error converting keytag: %s", err)
			}
			if uint16(dsKeytag) == keytag {
				fmt.Printf("DS with keytag %d exists in the registry\n", keytag)
				return true
			}
		}
		return false
	}

}

func getDnskeyFromDns(qname string) (map[uint16]string, error) {

	r, err := doQuery(qname, dns.TypeDNSKEY)
	// duplication of error checking from the doQuery function...
	if err != nil || r == nil {
		fmt.Fprintf(os.Stderr, "Cannot retrieve keys for %s: %s\n", qname, err)
		os.Exit(1)
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Fprintf(os.Stderr, "No such domain %s\n", qname)
		os.Exit(1)
	}

	if r.Rcode != dns.RcodeSuccess {
		fmt.Printf("Error in query for %s/DNSKEY: %s", qname, dns.RcodeToString[r.Rcode])
		os.Exit(1)
	}
	if !(r.Authoritative || r.AuthenticatedData) {
		fmt.Fprintf(os.Stderr, "response is neither authoritative nor validated")
		os.Exit(1)
	}

	// we should (prep, and) return a map of resource record objects instead of this.
	dnskeys := make(map[uint16]string)
	for _, ans := range r.Answer {
		switch rr := ans.(type) {
		case *dns.DNSKEY:
			_debug(fmt.Sprintf("got DNSKEY with keytag %d and flags %d", rr.KeyTag(), rr.Flags))
			switch rr.Flags {
			case 256:
				dnskeys[rr.KeyTag()] = "ZSK"
			case 257:
				dnskeys[rr.KeyTag()] = "KSK"
			default:
				fmt.Fprintf(os.Stderr, "Unknown flags in response: %d\n", rr.Flags)
				os.Exit(1)
			}
		}
	}
	if len(dnskeys) > 0 {
		return dnskeys, nil
	} else {
		return nil, errors.New("no keys found in DNS")
	}
}

func listDnskeyInDns(domain string) {
	dnskeys, err := getDnskeyFromDns(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erroring fetching DNSKEYs from DNS for domain %s: %s\n", domain, err)
		os.Exit(1)
	}
	switch len(dnskeys) {
	case 1:
		fmt.Printf("There is %d DNSKEY record\n", len(dnskeys))
	default:
		fmt.Printf("There are %d DNSKEY records\n", len(dnskeys))
	}
	for key := range dnskeys {
		fmt.Printf("  => DNSKEY %d (type %s)\n", key, dnskeys[key])
	}
}

func dnskeyExistsInDns(qname string, keytag uint16) bool {
	dnskeys, err := getDnskeyFromDns(qname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error retrieving DNSKEY records for %s: %s\n", qname, err)
		return false
	} else {
		for key := range dnskeys {
			if key == keytag {
				fmt.Printf("keytag %d exists with type %s\n", keytag, dnskeys[key])
				return true
			}
		}
		return false
	}
}

func _verbose(msgString string) {
	if !*verbose {
		return
	}
	fmt.Printf("%s\n", msgString)
}

func _debug(debugString string) {
	if !*debug {
		return
	}
	pc, _, no, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		fmt.Printf("DEBUG :: %s#%d :: %s\n", details.Name(), no, debugString)
	} else {
		fmt.Fprintf(os.Stderr, "fatal error determining debug calling function")
		os.Exit(1)
	}
}

func parseConfigurationFile(file string) (*configparser.ConfigParser, []error) {
	_debug(fmt.Sprintf("loading configuration from %s", file))
	p, err := configparser.NewConfigParserFromFile(file)
	var errs []error
	if err != nil {
		errStr := fmt.Sprintf("Error parsing config from %s: %s\n", file, err)
		fmt.Fprint(os.Stderr, errStr)
		errs = append(errs, errors.New(errStr))
		return nil, errs
	}

	// mandatory settings
	config["apiKey"], err = p.Get("api", "key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: no API key in the config file\n")
		errs = append(errs, errors.New("no API key in the config file"))
	} else {
		_verbose("API key set from configuration")
	}
	config["accountNumber"], err = p.Get("account", "number")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: no account number in the config file\n")
		errs = append(errs, errors.New("no account number in the config file"))
	} else {
		_verbose(fmt.Sprintf("account number set to %s from configuration", config["accountNumber"]))
	}

	// optionals, with fallback defaults
	config["nameserverAddr"], err = p.Get("nameserver", "address")
	if err != nil || config["nameserverAddr"] == "" {
		_verbose("no nameserver address in configuration; defaulting to 127.0.0.1")
		config["nameserverAddr"] = "127.0.0.1"
	} else {
		_verbose(fmt.Sprintf("nameserver address set to %s from configuration", config["nameserverAddr"]))
	}
	config["nameserverPort"], err = p.Get("nameserver", "port")
	if err != nil || config["nameserverPort"] == "" {
		_verbose("no nameserver port in configuration; defaulting to 53")
		config["nameserverPort"] = "53"
	} else {
		_verbose(fmt.Sprintf("nameserver port set to %s from configuration", config["nameserverPort"]))
	}

	// optional, where fallback defaults are baked in
	// for example, if you don't specify the endpoint, it'll default to prod
	config["apiEndpoint"], err = p.Get("api", "endpoint")
	if err != nil {
		_debug("no API endpoint in configuration, so falling back to production")
	}

	if errs == nil {
		return p, errs
	} else {
		return nil, errs
	}
}
