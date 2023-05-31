#! /usr/bin/env python3
#
# check security aspects of a second-level domain name
#
# Originally written by Jan Schaumann
# <jschauma@akamai.com> and Zuza Slawik
# <zslawik@akamai.com> in August 2022.

import sys
import json
import dns
import dns.dnssec
import dns.resolver
import argparse

EXIT_FAILURE = 1
EXIT_SUCCESS = 0

PROGNAME = 'domaincheck'
VERSION = '0.2'

# A data structure to hold our findings.
# This conveniently serializes directly to JSON.
RESULT = {}

# 'None' => use stub resolver
RESOLVER = None
OUTPUT_FORMAT = 'text'

LOOKUPS_WANTED = [ 'all' ]

LOOKUPS = {
    'CAA':     { 'domain_prefix': '',
                 'rr':            'CAA',
                 'pattern':       ''},

    'DMARC':   { 'domain_prefix': '_dmarc.',
                 'rr':            'TXT',
                 'pattern':       'DMARC1'},

    'DNSKEY':  { 'domain_prefix': '',
                 'rr':            'DNSKEY',
                 'pattern':       ''},

    'MX':      { 'domain_prefix': '',
                 'rr':            'MX',
                 'pattern':       ''},

    'MTA-STS': { 'domain_prefix': '_mta-sts.',
                 'rr':            'TXT',
                 'pattern':       'v=STSv1'},

    'SPF':     { 'domain_prefix': '',
                 'rr':            'TXT',
                 'pattern':       'v=spf1'},

    'TLS-RPT': { 'domain_prefix': '_smtp._tls.',
                 'rr':            'TXT',
                 'pattern':       'v=TLSRPTv1'},

    'TXT':     { 'domain_prefix': '',
                 'rr':            'TXT',
                 'pattern':       ''},

    'ZONEMD':  { 'domain_prefix': '',
                 'rr':            'ZONEMD',
                 'pattern':       ''}
}

LOOKUP_TYPES = sorted(list(LOOKUPS.keys()))

VALID_LOOKUP_TYPES = LOOKUP_TYPES + ['all']
VALID_FORMAT_TYPES = ['csv', 'json', 'text']

VERBOSITY = 0

###
# Functions
###


def getopts():
    global LOOKUPS_WANTED, OUTPUT_FORMAT, RESOLVER, VERBOSITY

    parser = argparse.ArgumentParser(
        description="check security aspects of a domain name")
    parser.add_argument('-V', '--version',
                        action='store_true',
                        dest='version',
                        required=False,
                        help='Print version number and exit.')

    parser.add_argument('-f', '--format',
                        default='text',
                        dest='format',
                        required=False,
                        type=str,
                        help='Specify the output format. ("' + "\", \"".join(VALID_FORMAT_TYPES) + '")')

    parser.add_argument('-r', '--resolver',
                        dest='resolver',
                        required=False,
                        type=str,
                        help='Use the given resolver for DNS lookups (default: stub resolver)')

    parser.add_argument('-t', '--type',
                        action='append',
                        default=[],
                        dest='type',
                        required=False,
                        type=str,
                        help='specify the type of check to perform ("' + "\", \"".join(VALID_LOOKUP_TYPES) + '")')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        dest='verbose',
                        required=False,
                        help='be verbose')

    args = parser.parse_args()

    if args.version:
        print("{:s}: {:s}".format(PROGNAME, VERSION))
        sys.exit(EXIT_SUCCESS)

    if args.format.lower() not in VALID_FORMAT_TYPES:
        print("Unsupported output format '{:s}' not one of '{:s}'.".format(args.format,
                                                                           "', '".join(VALID_FORMAT_TYPES)),
              file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    if len(args.type) > 0:
        LOOKUPS_WANTED = []

    for t in args.type:
        # We allow e.g., "-t CAA,DMARC":
        lookups = t.split(",")
        for l in t.split(","):
            if l not in VALID_LOOKUP_TYPES:
                print("Unsupported check '{:s}' not one of\n'{:s}'.".format(l,
                                                                    "', '".join(VALID_LOOKUP_TYPES)),
                        file=sys.stderr)
                sys.exit(EXIT_FAILURE)
            LOOKUPS_WANTED.append(l)

    OUTPUT_FORMAT = args.format.lower()
    RESOLVER = getResolver(args.resolver)
    VERBOSITY = args.verbose


def getResolver(resolver):
    r = dns.resolver.Resolver()

    if resolver != None:
        r.nameservers = [resolver]

    r.timeout = 1
    r.lifetime = 1

    return r


def lookup(dns_aspect, domain_name, rr, pattern=""):
    data = None

    if 'timeout' in RESULT[domain]:
        return

    verbose("Checking '{:s}' for domain '{:s}'...".format(dns_aspect, domain), 2)
    try:
        data = RESOLVER.resolve(domain_name, rr)
    except dns.resolver.LifetimeTimeout:
        RESULT[domain]['timeout'] = True
        print("DNS query for {:s} {:s} timed out.".format(domain_name, rr), file=sys.stderr)
    except Exception as e:
        if VERBOSITY > 3:
            print("Lookup Exception:", e, file=sys.stderr)
        return

    if data != None:
        for result in data:
            pattern_found = (pattern and (pattern in str(result)))

            if pattern == "" or pattern_found:
                result = str(result).strip('\"')
                if dns_aspect in RESULT[domain]:
                    RESULT[domain][dns_aspect]['count'] += 1
                    RESULT[domain][dns_aspect]['value'].append(result)
                else:
                    RESULT[domain][dns_aspect] = {
                        'count': 1,
                        'value': [result]
                    }

        if data.rdtype == dns.rdatatype.DNSKEY:
            validateDNSSEC(domain_name)

    return True
        

def performAllChecks(domain):
    for key in LOOKUPS.keys():
        config = LOOKUPS[key]
        lookup(key, config['domain_prefix'] + domain,
               config['rr'], config['pattern'])


def printCsv(domain, lineNum):
    if lineNum == 1:
        print("domain," + ",".join(LOOKUP_TYPES) + ",sig")

    print(domain + ",", end="")
    result = RESULT[domain]
    n = 0
    for key in LOOKUP_TYPES:
            n += 1
            value = 'no'

            if 'all' not in LOOKUPS_WANTED and key not in LOOKUPS_WANTED:
                value = '-'
            elif 'timeout' in result:
                value = '?'

            elif key == 'TXT':
                if key in result:
                    value = result['TXT']['count']
                else:
                    value = 0
            elif key in result:
                if key == 'MX' and result[key]['value'][0] == '0 .':
                    value = 'null'
                else:
                    value = 'yes'

            print(value, end="")

            if n == len(LOOKUP_TYPES):
                if 'DNSKEY' in RESULT[domain]:
                    print("," + RESULT[domain]['DNSKEY']['signature'], flush=True)
                else:
                    print(",missing", flush=True)
            else:
                print(",", end="")


def printJson():
    try:
        j = json.dumps(RESULT, indent = 2)
    except BaseException as err:
        print("Unable to jsonify result?\n{:s}".format(err), file=sys.stderr)
        sys.exit(EXIT_FAILURE)
    print(j)


def printText(domain, lineNum):
    if lineNum > 1:
        print()

    print(domain + ":")

    for key in LOOKUP_TYPES:
        if 'all' not in LOOKUPS_WANTED and key not in LOOKUPS_WANTED:
            continue
        value = "not found"
        if 'timeout' in RESULT[domain]:
            value = '?'
        elif key in RESULT[domain].keys():
            value = 'found'
            if key == 'TXT':
                value = str(RESULT[domain][key]['count'])
            elif key == 'DNSKEY':
                value += " (sig {:s})".format(RESULT[domain][key]['signature'])
            elif key == 'MX':
                if RESULT[domain][key]['value'][0] == '0 .':
                    value = 'null'

        print(key + ": " + value, flush=True)


def validateDNSSEC(domain):
    verbose("Validating DNSSEC for domain '{:s}'...".format(domain), 3)

    query = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)

    try:
        (response, tcp) = dns.query.udp_with_fallback(query,
                        RESOLVER.nameservers[0], timeout=1)
        if response.rcode() != 0:
            print("Unable to get DNSKEY for domain '{:s}' with DO flag set.".format(domain),
                file=sys.stderr)
            return
    except Exception as e:
        print(e)
        return

    rrsig = rrset = ""

    # We expect one RRSET for DNSKEY, one for RRSIG.
    if len(response.answer) != 2:
        print("Missing RRSIG for DNSKEY for domain '{:s}'.".format(domain),
                file=sys.stderr)
        print("Maybe you're using a non-validating (stub) resolver?".format(domain),
                file=sys.stderr)
        RESULT[domain]['DNSKEY']['signature'] = "missing"
        return

    if response.answer[0].rdtype == dns.rdatatype.RRSIG:
        rrsig, rrset = response.answer
    else:
        rrset, rrsig = response.answer

    keys = {dns.name.from_text(domain): rrset}
    try:
        dns.dnssec.validate(rrset, rrsig, keys)
    except dns.dnssec.ValidationFailure:
        print("Unable to validate DNSSEC signature for domain '{:s}'.".format(domain),
                file=sys.stderr)
        RESULT[domain]['DNSKEY']['signature'] = "invalid"
        return

    RESULT[domain]['DNSKEY']['signature'] = "valid"


def verbose(msg, level=1):
    if not VERBOSITY:
        return

    mark = "=" * level

    if not level or level <= VERBOSITY:
        print("{:s}> {:s}".format(mark, msg), file=sys.stderr)


###
# Main
###
if __name__ == "__main__":

    getopts()

    lineNum = 0
    for line in sys.stdin:
        lineNum += 1
    
        domain = line.rstrip()
    
        if domain == '':
            continue

        RESULT[domain] = {}
        verbose("Checking domain '{:s}'...".format(domain))
        if 'all' in LOOKUPS_WANTED:
            performAllChecks(domain)
        
        else:
            for l in LOOKUPS_WANTED:
                config = LOOKUPS[l]
                lookup(l, config['domain_prefix'] + domain,
                        config['rr'], config['pattern'])

        if OUTPUT_FORMAT == 'text':
            printText(domain, lineNum)

        elif OUTPUT_FORMAT == 'csv':
            printCsv(domain, lineNum)

        # "json" can only be printed after we've
        # processed all domains


    if OUTPUT_FORMAT == 'json':
        printJson()

    sys.exit(EXIT_SUCCESS)
