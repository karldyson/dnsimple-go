# DNSimple

## Introduction

After writing the perl module and scripts (see [repo](https://bitbucket.org/karldyson/dnsimple)) I decided that as
DNS Simple offer a Go library, I would use it as an excuse to duplicate the
perl scripts as an opportunity to learn Go.

So far, there are the following examples:

* dnsimple-ds
* dnsimple-cds
* dnsimple-ns
* dnsimple-domain
* dnsimple-contact

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

If the key is not being used to sign the DNSKEY record set, checks are made to
confirm if the key is the same algorithm as existing DS records. This is not
exhaustive, and depending on the other published DS records, may still cause
issues if published.

The user is prompted, if there are warnings, to see if they want to proceed.

This behaviour can be overridden and the operation forced with the -force flag.

The DS record will then be created from the DNSKEY and submitted to the API.

If the DS is being deleted, and is the last DS record, the user will be warned,
as this will result in the domain becoming insecure due to the chain of trust
being broken.

Again, this behaviour can be overridden with the -force flag

### dnsimple-cds

dnsimple-cds facilitates the automation of DS sync from published CDS records.

At the time of writing it runs on my hidden zone primary, which is configured to
recurse with validation for localhost.

The code checks the CDS record set and if there's a mismatch with the DS record
set, it makes the relevant modifications via the DNSimple API.

You can run it against other domains, but if they're not in the DNSimple acccount,
dry run mode will be set and it'll just tell you about the status.

If you don't supply a domain on the CLI, it'll loop through all of the domains in
the account.

If run directly on the zone primary, it'll also facilitate the intial population of
the DS record because it'll trust the auth response.

TODO includes tightening up that trust and consideration on having it look up the
auth servers for a domain to reduce caching effects, but it's running once per hour
from cron and is working well in my testing so far.

Changes in common.go introduced to support this need tidying up; but that's a
learning opportunity for me as I learn more go!

### dnsimple-ns

dnsimple-ns will eventually facilitate the manipulation of NS records in the 
domain delegation, as well as (hopefully) glue records. API doesn't support
these as yet.

### dnsimple-domain

dnsimple-domain facilitates domain actions; initially just listing the domains
in the account, and checking whether a domain is available to register.

If listing, and given a domain name, will list the details of the domain as
well as the details of the associated registrant.

Will eventually support registration and renewal.

### dnsimple-contact

dnsimple-contact facilitates contact actions; initially just listing those
in the account.

If listing, and given a contact's ID (from the list output), will list the
details of the contact.

Will eventually support creation and deletion of contacts.

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
