# DNSimple

## Introduction

After writing the perl module and scripts (see other repo) I decided that as
DNS Simple offer a go library, I would use it as an excuse to duplicate the
perl scripts in go as an opportunity to learn go.

So far, there are the following examples:

* dnsimple-ds

## Scripts

### dnsimple-ds

dnsimple-ds facilitates the manipulation of the DS records for a given domain
within the TLD's zonefile.

In the case of adding, given you should not want to add a DS record for a key
that is not published, checks will use a nameserver, defaulting to 127.0.0.1,
to query for the DNSKEYs for the domain.

It is expected that the server to either provide an authoritative response
(setting AA) or to conduct DNSSEC validation (setting AD). You should therefore
trust the server you set in the configuration if you're not running locally on
the authoritative server.

I run this locally on the auth primary for my zones.

Further checks will then be carried out in order to warn the user if:

* The requested key is a Zone Signing Key instead of a Key Signing Key
* The requested key is not being used to sign the DNSKEY record set

The user is prompted, if there are warnings, to see if they want to proceed.

This behaviour can be overridden and the operation forced with the -force flag.

The DS record will then be created from the DNSKEY and submitted to the API.

## Caveats

My first go at go. No pun intended. Might be awful. Might indeed eat your cat.

## Bug Reporting

Please use the issues feature, or, of course, offer to contribute.

## Licence and Copyright

This code is Copyright (c) 2024 Karl Dyson.

All rights reserved.

## Warranty

There's no warranty that this code is safe, secure, or fit for any purpose.

I'm not responsible if you don't read the code, check its suitability for your
use case, and wake up to find it's eaten your cat...
