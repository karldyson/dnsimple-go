/*

Copyright (c) 2024 Karl Dyson.
All rights reserved.

* Add some annotation and/or docs
* Add a license, copyright, etc
* getApiClient feels a bit light on error catching and handling...
* getDnskeyFromDns feels like its duplicating a lot of the RCODE checking from doQuery...?
  double check, but mindful of whether everything expects an answer as opposed to delegation etc?
* still feels like we're a bit muddy on the difference between verbose and debug output...
* methods should mostly return errors rather than exiting... main() may want the option to handle it and carry on regardless
* methods should return brief errors, as we have a bunch of things just build on build on.
  debug and/or log, and return just the error, which the calling function or code can deal with and/or display
* deal with pagination in API calls...

*/

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/bigkevmcd/go-configparser"
	"github.com/dnsimple/dnsimple-go/dnsimple"
	"github.com/miekg/dns"
)

type configuration struct {
	apiKey         string
	accountNumber  string
	nameserverAddr string
	nameserverPort string
	dsDigestType   uint8
	apiEndpoint    string
}

// global variable declarations
var (
	configFile     = flag.String("config", "/usr/local/etc/dnsimple.cfg", "configuration file") // the configuration file
	debugOutput    = flag.Bool("debug", false, "enable debug output")                           // debug?
	verboseOutput  = flag.Bool("verbose", false, "verbose output")                              // verbosity?
	version        = flag.Bool("version", false, "the code version")
	revision       = flag.Bool("revision", false, "revision and build information")
	forceOperation = flag.Bool("force", false, "force the current operation ignoring any warnings (will still be output)")
	config         configuration
	tc             *http.Client     // pointer to the global token client object
	apiClient      *dnsimple.Client // pointer to the global API client object
	versionString  string           = "devel"
)

// askUserYesNo takes a string and prompts the user with that string and a y/N
// If the user replies with y, Y, yes, Yes, then it returns true
// Anything else returns false
// It takes one parameter, the string to be prompted to the user
// It returns one bool depending on whether the user said Y or not.
func askUserYesNo(s string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", s)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error requesting confirmation from user: %s\n", err)
		os.Exit(1)
	}
	response = strings.ToLower(strings.TrimSpace(response))
	_debug(fmt.Sprintf("user replied to prompt with [%s]", response))
	if response == "y" || response == "yes" {
		_debug("returning true")
		return true
	} else {
		// you can
		// else if response == "n" || response == "no" {
		// and wrap in a for {} to force y or n
		_debug("returning false")
		return false
	}
}

// doQuery performs DNS lookups. It takes two parameters, the domain to be looked up and the qtype
// queries are performed over TCP, with DO and RD set
// queries are sent to the nameserver and port parsed from the config
// It returns the dns response object amd an error object
func doQuery(qname string, qtype uint16) (*dns.Msg, error) {

	_debug(fmt.Sprintf("Sending query for %s/%s to %s", qname, dns.TypeToString[qtype], net.JoinHostPort(config.nameserverAddr, config.nameserverPort)))

	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // do DNSKEY (set DO, as we want AD)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	r, rtt, err := c.Exchange(m, net.JoinHostPort(config.nameserverAddr, config.nameserverPort))
	_verbose(fmt.Sprintf("Response received for %s/%s from %s:%s in %s", qname, dns.TypeToString[qtype], config.nameserverAddr, config.nameserverPort, rtt))
	if err != nil {
		_debug(fmt.Sprintf("Error: query for %s/%s resulted in error: %s", qname, dns.TypeToString[qtype], err))
		return nil, err
	}
	if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
		_debug(fmt.Sprintf("query for %s/%s resulted in rcode %s", qname, dns.TypeToString[qtype], dns.RcodeToString[r.Rcode]))
		_debug(fmt.Sprintf("header is:\n%+v", r.MsgHdr))
		return r, err
	}
	return nil, fmt.Errorf("rcode: %s", dns.RcodeToString[r.Rcode])
}

// getApiClient either creates or passes back an existing globel client object
// it takes no parameters
// it returns a pointer to the client object
func getApiClient() *dnsimple.Client {
	// feels like there's not a lot of error catching/handling going on here...
	if tc == nil {
		_debug("token client does not exist, so creating it")
		tc = dnsimple.StaticTokenHTTPClient(context.Background(), config.apiKey)
	} else {
		_debug("using existing token client")
	}
	if apiClient == nil {
		_debug("api client doesn't exist, so creating it")
		apiClient = dnsimple.NewClient(tc)
	} else {
		_debug("using existing api client object")
	}
	if apiClient != nil && config.apiEndpoint != "" {
		_debug(fmt.Sprintf("setting API endpoint to %s", config.apiEndpoint))
		//		apiClient.BaseURL = "https://api.sandbox.dnsimple.com"
		apiClient.BaseURL = config.apiEndpoint
	}
	return apiClient
}

// domainExistsInAccount checks in the account via the API to see if the domain exists
// Takes one parameter, the domain to be checked
// Returns bool indicating if the domain is in the account, and whether there were any errors performing the check
func domainExistsInAccount(domain string) (bool, error) {
	d, e := getDomainsInAccount(domain)
	if e != nil {
		_debug(fmt.Sprintf("Error: error fetching domains from API: %s", e))
		return false, fmt.Errorf("error fetching domains from API: %s", e)
	}
	for _, domainRecord := range d {
		_debug(fmt.Sprintf(" => got domain %s", domainRecord.Name))
		if domainRecord.Name == domain {
			return true, nil
		}
	}
	return false, errors.New("lost")
}

// getDomainsInAccount retrieves a list of domains in the account
// Takes one parameter, allowing the list to be matched to a subset
// Returns a map of Domain objects and an error object
func getDomainsInAccount(domain string) ([]dnsimple.Domain, error) {
	client := getApiClient()
	var listOptions dnsimple.DomainListOptions
	if domain != "" {
		_debug(fmt.Sprintf("constraining list to match [%s]", domain))
		listOptions.NameLike = &domain
	}
	sortOption := "expiration:desc"
	listOptions.ListOptions.Sort = &sortOption
	r, err := client.Domains.ListDomains(context.Background(), config.accountNumber, &listOptions)
	if err != nil {
		_debug(fmt.Sprintf("Error: error fetching domains from the API: %s", err))
		return nil, fmt.Errorf("error fetching domains from API: %s", err)
	}
	_debug(fmt.Sprintf("HTTP response code was %s", r.HTTPResponse.Status))

	// this is likely the first API call where we may want to add pagination handling...
	_debug(fmt.Sprintf("we are on page %d of %d at %d per page", r.Pagination.CurrentPage, r.Pagination.TotalPages, r.Pagination.PerPage))
	return r.Data, nil
}

// listDomainsInAccount produces pretty output of the domains in the account with their expiry dates.
func listDomainsInAccount() {
	d, e := getDomainsInAccount("")
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error: error fetching domains from API: %s", e)
		os.Exit(1)
	}
	strwidth := 0
	for _, dr := range d {
		if len(dr.Name) > strwidth {
			strwidth = len(dr.Name)
		}
	}
	for _, dR := range d {

		now := time.Now()
		var days float64
		var dayStr string
		tt, err := time.Parse(time.RFC3339, dR.ExpiresAt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse expiry date (%s): %s\n", dR.ExpiresAt, err)
			dayStr = ""
		} else {
			days = tt.Sub(now).Hours() / 24
			dayStr = fmt.Sprintf("(%d days)", int(days))
		}

		name := dR.Name + strings.Repeat(".", (strwidth-len(dR.Name)))
		fmt.Printf("  => %-*s; expiry: %s %s\n", strwidth, name, dR.ExpiresAt, dayStr)
	}
}

// checkDomainStatus checks with a domain is available to be registered and whether it's a premium domain
// takes one parameter, the domain to be queried
// returns two parameters; boolean on whether the domain is available, and error if encountered
func checkDomainStatus(domain string) (*dnsimple.DomainCheckResponse, error) {
	client := getApiClient()
	r, e := client.Registrar.CheckDomain(context.Background(), config.accountNumber, domain)
	if e != nil {
		return nil, fmt.Errorf("error checking status of domain %s: %s", domain, e)
	}
	_debug(fmt.Sprintf("%+v", r.Data))
	return r, nil
}

// getDomainPrice fetches the prices applicable to the domain
// takes one parameter, that being the domain to be checked
// returns a DomainPriceResponse object and an error object
func getDomainPrice(domain string) (*dnsimple.DomainPriceResponse, error) {
	client := getApiClient()
	p, e := client.Registrar.GetDomainPrices(context.Background(), config.accountNumber, domain)
	if e != nil {
		return nil, fmt.Errorf("error checking price of domain %s: %s", domain, e)
	}
	_debug(fmt.Sprintf("%+v", p.Data))
	return p, nil
}

// getNsFromRegistry uses the registrar API to get a list of the NS records in the registry
// It takes one parameter, the domain to be queried
// It returns two parameters, the NS record response and an error object
func getNsFromRegistry(domain string) (*dnsimple.DelegationResponse, error) {
	client := getApiClient()
	nsResponse, err := client.Registrar.GetDomainDelegation(context.Background(), config.accountNumber, domain)
	if err != nil {
		errorString := fmt.Sprintf("Error: error fetching NS records from registry for domain %s: %s\n", domain, err)
		return nil, errors.New(errorString)
	}
	return nsResponse, nil
}

// listNsInRegistry produces pretty (!!) output of NS records found in the registry
// It takes one parameter, that being the domain to be queried
// It returns nothing.
func listNsInRegistry(domain string) {
	nsRecords, err := getNsFromRegistry(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error fetching NS records from the registry: %s\n", err)
		os.Exit(1)
	}
	switch len(*nsRecords.Data) {
	case 0:
		fmt.Println("There are no NS records")
	case 1:
		fmt.Printf("There is %d NS record\n", len(*nsRecords.Data))
	default:
		fmt.Printf("There are %d NS records\n", len(*nsRecords.Data))
	}
	for _, ns := range *nsRecords.Data {
		fmt.Printf("  => NS %s\n", ns)
	}
}

// getDsFromRegistry uses the registrar API to get a list of the DS records in the registry
// It takes one parameter, the domain to be queried
// It returns two parameters, the DS record response and an error object
func getDsFromRegistry(domain string) (*dnsimple.DelegationSignerRecordsResponse, error) {
	client := getApiClient()
	dsResponse, err := client.Domains.ListDelegationSignerRecords(context.Background(), config.accountNumber, domain, nil)
	if err != nil {
		errorString := fmt.Sprintf("Error: error fetching DS records from registry for domain %s: %s\n", domain, err)
		return nil, errors.New(errorString)
	}
	return dsResponse, nil
}

// listDsInRegistry produces pretty (!!) output of DS records found in the registry
// It takes one parameter, that being the domain to be queried
// It returns nothing.
func listDsInRegistry(domain string) {
	dsRecords, err := getDsFromRegistry(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error fetching DS records from the registry: %s\n", err)
		os.Exit(1)
	}
	switch len(dsRecords.Data) {
	case 0:
		fmt.Println("There are no DS records")
	case 1:
		fmt.Printf("There is %d DS record\n", len(dsRecords.Data))
	default:
		fmt.Printf("There are %d DS records\n", len(dsRecords.Data))
	}
	for _, ds := range dsRecords.Data {
		fmt.Printf("  => DS %5s %s %s %s\n", ds.Keytag, ds.Algorithm, ds.DigestType, ds.Digest)
	}
}

// dsExistsInRegistry determines whether a specific DS record exists in the registry
// It takes two parameters, the domain to be queried and the keytag to be verified
// It returns a DS object, an error object and a boolean
// The error will contain any errors encountered
// The boolean determines whether the DS record exists
// Hence, the combination determines the status:
// error == nil, ok bool is true => DS exists (DS will be in the DS object)
// error != nil, ok bool is true => DS does not exist
// error != nil, ok bool is false => an error occurred trying
func dsExistsInRegistry(domain string, keytag uint16) (dnsimple.DelegationSignerRecord, bool, int, error) {
	dsRecords, err := getDsFromRegistry(domain)
	var dsr dnsimple.DelegationSignerRecord
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error retrieving list of keys for %s: %s\n", domain, err)
		return dsr, false, 0, fmt.Errorf("error retrieving list of keys: %s", err)
	} else {
		dsCount := len(dsRecords.Data)
		for _, ds := range dsRecords.Data {
			_debug(fmt.Sprintf("got ds with keytag %s", ds.Keytag))
			dsKeytag, err := strconv.ParseUint(ds.Keytag, 10, 16)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error converting keytag string (%s) to integer: %s", ds.Keytag, err)
				os.Exit(1)
			}
			if uint16(dsKeytag) == keytag {
				_debug(fmt.Sprintf("DS with keytag %d is one of %d DS records in the registry", keytag, dsCount))
				return ds, true, dsCount, nil
			}
		}
		return dsr, true, dsCount, fmt.Errorf("DS record does not exist in %d DS records", dsCount)
	}

}

// getDnskeyFromDns looks up DNSKEY records in DNS
// It takes one parameter, the domain to be queried
// It returns a map of DNSKEYs indexed by keytag and an error object
// It expects the query to be done with RD and DO and that the response returned to it
// is either authoritative (AA) or validated (AD) - you should trust the validator if the latter!
func getDnskeyFromDns(qname string) (map[uint16]dns.DNSKEY, error) {

	r, err := doQuery(qname, dns.TypeDNSKEY)
	// duplication of error checking from the doQuery function...
	if err != nil || r == nil {
		_debug(fmt.Sprintf("Error: cannot retrieve keys for %s: %s", qname, err))
		return nil, err
	}
	if r.Rcode == dns.RcodeNameError {
		_debug(fmt.Sprintf("Error: no such domain %s", qname))
		return nil, errors.New("no such domain")
	}

	if r.Rcode != dns.RcodeSuccess {
		_debug(fmt.Sprintf("Error in query for %s/DNSKEY: %s", qname, dns.RcodeToString[r.Rcode]))
		return nil, fmt.Errorf("error: %s", dns.RcodeToString[r.Rcode])
	}
	if !(r.Authoritative || r.AuthenticatedData) {
		_debug("response is neither authoritative nor validated")
		return nil, errors.New("response is neither authoritative nor validated")
	} else {
		_verbose(fmt.Sprintf("Response received is authoritative [%v] or validated [%v]", r.Authoritative, r.AuthenticatedData))
	}

	dnskeys := make(map[uint16]dns.DNSKEY)
	for _, ans := range r.Answer {
		switch rr := ans.(type) {
		case *dns.DNSKEY:
			_debug(fmt.Sprintf("got DNSKEY with keytag %d and flags %d", rr.KeyTag(), rr.Flags))
			dnskeys[rr.KeyTag()] = *rr
		}
	}
	if len(dnskeys) > 0 {
		return dnskeys, nil
	} else {
		return nil, errors.New("no keys found in DNS")
	}
}

// listDnsketInDns produces pretty output of the DNSKEY records found in DNS
// It takes one parameter, that being the domain to be queried
// It returns nothing.
func listDnskeyInDns(domain string) {
	dnskeys, err := getDnskeyFromDns(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error fetching DNSKEYs from DNS for domain %s: %s\n", domain, err)
		os.Exit(1)
	}
	switch len(dnskeys) {
	case 0:
		fmt.Println("There are no DNSKEY records")
	case 1:
		fmt.Printf("There is %d DNSKEY record\n", len(dnskeys))
	default:
		fmt.Printf("There are %d DNSKEY records\n", len(dnskeys))
	}
	for key := range dnskeys {
		k := dnskeys[key]
		var keyType string
		switch k.Flags {
		case 256:
			keyType = "ZSK"
		case 257:
			keyType = "KSK"
		default:
			fmt.Fprintf(os.Stderr, "Error: DNSKEY keytag %d in domain %s has unknown flags: %d\n", key, domain, k.Flags)
			os.Exit(1)
		}
		fmt.Printf("  => DNSKEY; keytag: %5d; flags: %d (%s); Algorithm: %d (%s)\n", key, k.Flags, keyType, k.Algorithm, dns.AlgorithmToString[k.Algorithm])
	}
}

// dnskeyExistsInDns determinies whether a DNSKEY exists in DNS
// It takes two parameters, the domain to be queried and the keytag of the DNSKEY
// It returns a DNSKEY object and an error object
// If the error is set, either the key does not exist, or there was an error checking
// If the error is unset, the DNSKEY will be found in the returned object
// I'm debating switching to the method in dsExistsInRegistry as it allows the caller to
// determine whether there was an actual error, or the key doesn't exist.
func dnskeyExistsInDns(qname string, keytag uint16) (dns.DNSKEY, error) {
	dnskeys, err := getDnskeyFromDns(qname)
	var r dns.DNSKEY
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: error retrieving DNSKEY records for %s: %s\n", qname, err)
		return r, err
	} else {
		for key := range dnskeys {
			if key == keytag {
				_debug(fmt.Sprintf("keytag %d exists with type %d", keytag, dnskeys[key].Flags))
				return dnskeys[key], nil
			}
		}
		return r, errors.New("key doesn't exist")
	}
}

// _verbose takes a string and only outputs it if verbosity is requested via the -verbose CLI flag
func _verbose(msgString string) {
	if !*verboseOutput {
		return
	}
	fmt.Printf("%s\n", msgString)
}

// _debug takes a string and only outputs it if debug mode is enabled with the -debug CLI flag
// function adds the calling function and line number to the output to aid debugging
func _debug(debugString string) {
	if !*debugOutput {
		return
	}
	pc, _, no, ok := runtime.Caller(1)
	details := runtime.FuncForPC(pc)
	if ok && details != nil {
		fmt.Printf("DEBUG :: %s#%d :: %s\n", details.Name(), no, debugString)
	} else {
		fmt.Fprintf(os.Stderr, "Error: fatal error determining debug calling function")
		os.Exit(1)
	}
}

// parseConfigurationFile parses the configuration file
// It takes one parameter, the config file. defaulting if -config is not passed on the CLI is handled in the flag parsing
// It returns a config parser object and an array of errors
// Mandatory items such as the API key and account number cause errors if missing
// Items that can fall back to defaults, such as the nameserver, do so
// Note that NOT passing an endpoint to the library causes it to default to production and so we don't need to
func parseConfigurationFile(file string) (*configparser.ConfigParser, []error) {
	_debug(fmt.Sprintf("loading configuration from %s", file))
	p, err := configparser.NewConfigParserFromFile(file)
	var errs []error
	if err != nil {
		errStr := fmt.Sprintf("error parsing config from %s: %s\n", file, err)
		fmt.Fprint(os.Stderr, errStr)
		errs = append(errs, errors.New(errStr))
		return nil, errs
	}

	// mandatory settings
	config.apiKey, err = p.Get("api", "key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: no API key in the config file\n")
		errs = append(errs, errors.New("no API key in the config file"))
	} else {
		_debug("API key set from configuration")
	}
	config.accountNumber, err = p.Get("account", "number")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: no account number in the config file\n")
		errs = append(errs, errors.New("no account number in the config file"))
	} else {
		_debug(fmt.Sprintf("Account number set to %s from configuration", config.accountNumber))
	}

	// optionals, with fallback defaults
	config.nameserverAddr, err = p.Get("nameserver", "address")
	if err != nil || config.nameserverAddr == "" {
		_debug("no nameserver address in configuration; defaulting to 127.0.0.1")
		config.nameserverAddr = "127.0.0.1"
	} else {
		_debug(fmt.Sprintf("nameserver address set to %s from configuration", config.nameserverAddr))
	}
	config.nameserverPort, err = p.Get("nameserver", "port")
	if err != nil || config.nameserverPort == "" {
		_debug("no nameserver port in configuration; defaulting to 53")
		config.nameserverPort = "53"
	} else {
		_debug(fmt.Sprintf("nameserver port set to %s from configuration", config.nameserverPort))
	}
	tmp, err := p.Get("ds", "digest_type")
	if err != nil {
		_debug("no DS record digest type in configuration; defaulting to 2 (SHA-256)")
		config.dsDigestType = 2
	} else {
		dsDigestType, err := strconv.ParseUint(tmp, 10, 8)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error converting digest type configuration string (%s) to integer: %s", tmp, err)
			os.Exit(1)
		}
		config.dsDigestType = uint8(dsDigestType)
		_debug(fmt.Sprintf("DS records digest type set to %d from configuration", config.dsDigestType))
	}
	// optional, where fallback defaults are baked in
	// for example, if you don't specify the endpoint, it'll default to prod
	config.apiEndpoint, err = p.Get("api", "endpoint")
	if err != nil {
		_debug("no API endpoint in configuration, so falling back to production")
	}

	if errs == nil {
		return p, errs
	} else {
		return nil, errs
	}
}
