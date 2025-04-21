#!/usr/bin/env python3
'''
Lookup SMPT TLS policy published by email domains passed on the command line
Output:
- CSV header if called with --header
- CSV lines for each domain publishing an MX valid record:
  - domain: domain from command line arguments
  - has_smtpdane: 1 if a TLSA record is published for _25._tcp.<domain>, 0 otherwise
  - has_mtasts: 1 if a "v=STSv1..." TXT record is published for _mta-sts.<domain> 
  - has_any: has_smtpdane or has_mtasts
  - mx_records: published valid MX ordered by priority, separate by newline
  - smtpdane_records: published SMTP DANE TLSA records, separate by newline
  - mtasts_records: published MTA STS TXT records, separate by newline
  Published records are not validated.
'''
import sys
import dns.resolver
import argparse

def validmx(mx):
    '''
    Return False for MX records that do not represent a SMTP server:
    - .:  Null MX as defined in RFC 7505 meaning that the domain doesn't accept any email.
    - 0.0.0.0. and localhost.: Sometimes used in indicate the same as
    '''
    match mx:
        case '.' | '0.0.0.0.' | 'localhost.':
            return False
        case _:
            return True
        
def lookupmx(resolver, d):
    '''
    Return list of valid MX domains, ordered by priority (and alphabetically) and
    if the list is empty an error text detailing why.
    '''
    mxs = []
    authenticated = False
    error = ''
    try:
        answer = resolver.resolve(d, "MX")
        authenticated = (answer.response.flags & dns.flags.AD) != 0
        # sort records by name to make mxs canonical
        records = sorted(answer, key=lambda r: r.exchange.to_unicode().lower())
        # sort preferred MX first
        records = sorted(records, key=lambda r: r.preference)
        # convert bytes to str
        mxsunfiltered = [ r.exchange.to_unicode().lower() for r in records ]
        # remove invalid MX
        mxs = list(filter(validmx, mxsunfiltered))
        if len(mxs) == 0:
            error = "no valid MX: " + ", ".join(mxsunfiltered)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
        error = str(e)
    return mxs, authenticated, error

def lookupdane(resolver, mxs):
    '''
    Lookup SMTP DANE TLSA records for MX domains in mxs
    Return
        1, TLSA record
        or
        0, error
    '''
    error = ''
    for mx in mxs:
        try:
            answer = resolver.resolve("_25._tcp." + mx, "TLSA")
            dane = "\n".join([ str(r) for r in answer ])
            return 1, dane
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
           error = str(e)
    return 0, error

def indicator(b):
    if (b):
        return 1
    else:
        return 0
    
def is_sts(s):
    '''
    Return True if s looks like a MSA STS TXT record without validating it
    '''
    return s.lower().startswith('v=stsv1')

def lookupsts(resolver, d):
    '''
    Return (1, valid looking MTA STS TXT records for domain d, separated by newline)
    or (0, error details)
    '''
    txts = []
    try:
        answer = resolver.resolve("_mta-sts." + d, "TXT")
        # r.strings is a tuple of bytes as per RFC1035, which we concatenate
        txts = [ b''.join(r.strings).decode() for r in answer ]
        # filter for v=STSv1
        txts = [ t for t in txts if is_sts(t) ]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
        return 0, str(e)
    return indicator(len(txts)), '\n'.join(txts)

def lookupdomain(resolver, d):
    '''
    Print CSV record for domain d
    '''
    mxs, mxauth, mxerror = lookupmx(resolver, d)
    if (len(mxs) == 0):
        mxdetails = mxerror
    else:
        mxdetails = "\n".join(mxs)
    daneflag, danedetails = lookupdane(resolver, mxs)
    stsflag, stsdetails = lookupsts(resolver, d)
    print(f'{d},{indicator(len(mxs))},{daneflag},{stsflag},{indicator(daneflag or stsflag)},{indicator(mxauth)},"{mxdetails}","{danedetails}","{stsdetails}"', flush=True)

def parse_args(resolver):
    argparser = argparse.ArgumentParser(description='Lookup SMTP DANE and MTA STS and output results in CSV format', 
                                        epilog=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    argparser.add_argument('domains', nargs='*',
                           help='domais to check')
    argparser.add_argument('-t', '--timeout', type=int, default=resolver.timeout,
                           help='number of seconds to wait for nameserver response (default: %(default)d)')
    argparser.add_argument('-l', '--lifetime', type=int, default=resolver.lifetime,
                           help='number of seconds to spend trying to get an answer to the question (default: %(default)d)')
    argparser.add_argument('-r', '--retry', action=argparse.BooleanOptionalAction, default=False,
                           help='retry on SERVFAIL (default: no retry)')
    argparser.add_argument('-H', '--header', action=argparse.BooleanOptionalAction,
                           help='print CSV header (default: no header)')
    argparser.add_argument('-s', '--nameserver', type=str, nargs=1, action='extend',
                           help='use custom nameserver, repeat to add multiple')
    return argparser.parse_args()

def configure_resolver(resolver, args):
    if args.nameserver:
        resolver.nameservers = args.nameserver
    resolver.timeout = args.timeout
    resolver.lifetime = args.lifetime
    resolver.retry_servfail = args.retry
    resolver.set_flags(dns.flags.RD | dns.flags.AD) # RD recursion desired, AD authenticated data

if __name__ == '__main__':
    resolver = dns.resolver.Resolver()
    args = parse_args(resolver)
    configure_resolver(resolver, args)
    try:
        if args.header:
            print("domain,has_mx,has_smtpdane,has_mtasts,has_any,mx_auth,mx_details,smtpdane_details,mtasts_details")
        for domain in args.domains:
            lookupdomain(resolver, domain)
    except KeyboardInterrupt:
        pass
