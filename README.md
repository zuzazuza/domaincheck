domaincheck -- check certain security aspects of a second-level domain name
===========================================================================

Many security mechanisms can (only) be set on the
second-level domain name, yet have a broad and often
times not entirely obvious impact on all of its child
domains.

The `domaincheck(1)` utility can be used to perform a
quick and simple assessment of a number of such
checks.

Checks of interest that this tool performs include:

- CAA
- DMARC
- DNSSEC
- MTA-STS
- MX
- SPF
- TLS-RPT
- count / list of additional TXT records
- ZONEMD


Installation
============

`domaincheck(1)` is written using Python 3 and it
requires the 'dnspython' and 'cryptography' python
modules.  You can install these manually yourself and
then run `sudo make install` to install
`domaincheck(1)` into '/usr/local'.

If you prefer a different PREFIX, you can run for
example:

```
$ make PREFIX=~ install
```

There's also a `setup.py` file in this directory, and
running `make pip-install` will use that via `pip3`
(or whatever you set `PIP` to) to resolve the
dependencies and install `domaincheck(1)` into your
python prefix:

```
$ make pip-install
```

---

```
NAME
     domaincheck – check security aspects of a second-level domain name

SYNOPSIS
     domaincheck [-Vhv] [-f format] [-r resolver] [-t type]

DESCRIPTION
     The domaincheck utility performs a number of DNS-based checks on the domain
     names given as input.

OPTIONS
     The following options are supported by domaincheck:

     -V 	   Print version number and exit.

     -f format	   Specify the output format.  Valid formats are 'csv', 'json',
		   and 'text' (default: ´text').  for details.

     -h 	   Print a short help message and exit.

     -r resolver   Use the given resolver for DNS lookups (default: stub
		   resolver).  See RESOLVER for details.

     -t type	   Specify the type of check to perform (default: all).  See
		   DETAILS for a description of the supported checks.

     -v 	   Be verbose.	Can be specified multiple times.

DETAILS
     Many security mechanisms can (only) be set on the second-level domain name,
     yet have a broad and often times not entirely obvious impact on all of its
     child domains.

     The domaincheck utility can be used to perform a quick and simple
     assessment of a number of such checks.  It will read second-level domain
     names from stdin one name per line and then perform the following checks:

     CAA       Identify whether the domain has any CAA records sets.  See
	       RFC8659.

     DMARC     Identify whether DMARC is set for the given domain.  See RFC7489.

     DNSKEY    Identify whether the domain is has a DNSKEY record and if so,
	       whether it has a valid DNSSEC signature.  See RFC4034.

     MX        Identify whether the domain has any MX records set.  If so, check
	       for the existence of a "Null MX" service record.  See RFC7505.

     MTA-STS   Identify whether the domain uses SMTP MTA Strict Transport
	       Security.  See RFC8461.

     SPF       Identify whether the domain uses the Sender Policy Framework.
	       See RFC7208.

     TLS-RPT   Identify whether the domain uses SMTP TLS Reporting.  See
	       RFC8460.

     TXT       Report on any additional DNS TXT records not relating to any of
	       the above.

     ZONEMD    Report on the presence of the ZONEMD record.  See RFC8976.

     Each of these checks can be specified to the -t flag; multiple checks can
     be specified as a comma-separated list or as repeated flags.  If no list of
     checks is specified, then domaincheck will perform all of the above checks.

RESOLVER
     By default, domaincheck will perform DNS lookups against the default stub
     resolver via the operating system's standard domain name resolution
     library.

     To use a specific resolver, the user may use the -r flag and provide a
     hostname or IP address, in which case domaincheck will directly query that
     resolver.

     Finally, if the user specifies the special string ´auth' to the -r flag,
     then domaincheck will attempt to directly query one of the authoritative
     nameservers for the given domain.

EXAMPLES
     To perform a full analysis of the supported aspects for the domain name
     'akamai.com':

	   echo akamai.com | domaincheck

     To verbosely look up only CAA and SPF information for the domains found in
     the file 'domains':

	   domaincheck -v -v -t caa,spf <domains

     To generate json output for the information determined by asking the
     respective authoritative resolvers of each CNAME found in the 'akam.ai'
     zone file:

	   awk '/CNAME.*\.$/ { print $NF }' akam.ai | \
		   sort -u |			      \
		   domaincheck -j -r auth

HISTORY
     domaincheck was originally written by Jan Schaumann ⟨jschauma@akamai.com⟩
     and Zuza Slawik ⟨zslawik@akamai.com⟩ in July 2022.

BUGS
     Please file bug reports and feature requests via a PR in git or by emailing
     the authors.
```
