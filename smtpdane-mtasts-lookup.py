#!/usr/bin/env python3
'''
Lookup SMPT TLS policy published by email domains passed on the command line
Output:
- CSV header if called with --header
- CSV lines for each domain publishing an MX valid record:
  - domain: domain from command line arguments
  - has_mx: 1 if `domain` has an MX record, 0 otherwise
  - has_mxauth: 1 if the `domain` MX record lookup was DNSSEC authenticated (by the nameserver), 0 otherwise
  - has_mxtlsa: 1 if a TLSA record exists for _25._tcp.<preferred MX domain>, 0 otherwise
  - has_smtpdane: 1 if `has_mxauth`=1 and `hasmxtlsa`=1, 0 otherwise
  - has_mtasts: 1 if a "v=STSv1..." TXT record is published for _mta-sts.<domain>, 0 otherwise
  - has_any: has_smtpdane or has_mtasts
  - mx_details: published valid MX ordered by priority, separate by `delimiter` or error message if has_mx = 0
  - mxtlsa_details: published SMTP DANE TLSA records, separate by `newline` or error message if has_mxtlsa = 0
  - mtasts_details: published MTA STS TXT records, separate by newline
  Published records are not validated.
'''
from typing import List, Tuple
import dns.resolver
import argparse

def validmx(mx: str) -> bool:
    '''
    Return False for MX records that do not represent a SMTP server:
    - .:  Null MX as defined in RFC 7505 meaning that the domain doesn't accept any email.
    - 0.0.0.0. and localhost.: Sometimes used in indicate the same as .
    '''
    match mx:
        case '.' | '0.0.0.0.' | 'localhost.':
            return False
        case _:
            return True
        
def lookupmx(resolver: dns.resolver.Resolver, domain: str) -> Tuple[List[str], bool, str]:
    '''
    Return a tuple consiting of
    - list of valid MX domains, ordered by priority (and alphabetically), removing invalid MX
    - authenticated flag, True if AD flag ist present in the response
    - error details of failed resolver lookup or the removed MXs if all are invalid
    '''
    mxs = []
    authenticated = False
    error = ''
    try:
        answer = resolver.resolve(domain, "MX")
        # the Answer class calls resolve_chaining to resolves up to dns.message.MAX_CHAIN (16) CNAME pointers in the response
        # AFAIU the AD flag applies to the response including all CNAME and records 
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

def lookuptlsa(resolver: dns.resolver.Resolver, domain: str, port: int, delimiter: str) -> Tuple[int, str]:
    '''
    Lookup TLSA record for domain and port
    Return
        1, TLSA records
        or
        0, error
    '''
    error = ''
    try:
        answer = resolver.resolve(f"_{port}._tcp.{domain}", "TLSA")
        dane = delimiter.join([ str(r) for r in answer ])
        return 1, dane
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
        error = str(e)
    return 0, error

def indicator(b: bool) -> int:
    '''return bool encoded as int'''
    if (b):
        return 1
    else:
        return 0
    
def is_sts(txt: str) -> bool:
    '''
    Return True if s looks like a MSA STS TXT record without validating it
    '''
    return txt.lower().startswith('v=stsv1')

def lookupsts(resolver: dns.resolver.Resolver, domain: str, delimiter: str) -> Tuple[int, str]:
    '''
    Return (1, valid looking MTA STS TXT records for domain d, separated by newline)
    or (0, error details)
    '''
    txts = []
    try:
        answer = resolver.resolve("_mta-sts." + domain, "TXT")
        # r.strings is a tuple of bytes as per RFC1035, which we concatenate
        txts = [ b''.join(r.strings).decode() for r in answer ]
        # filter for v=STSv1
        txts = [ t for t in txts if is_sts(t) ]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
        return 0, str(e)
    return indicator(len(txts)), delimiter.join(txts)

def lookupdomain(resolver: dns.resolver.Resolver, domain: str, delimiter: str) -> None:
    '''
    Print CSV record for domain d
    '''
    mxs, mxauth, mxerror = lookupmx(resolver, domain)
    if (len(mxs) > 0):
        mxdetails = delimiter.join(mxs)
        # lookup TLSA record for the preferred MX https://datatracker.ietf.org/doc/html/rfc7672#section-2.2.1
        mxtlsaflag, mxtlsadetails = lookuptlsa(resolver, mxs[0], 25, delimiter)  
    else:
        mxdetails = mxerror
        mxtlsaflag, mxtlsadetails = 0, ''
        # # If `domain` has no MX, but A/AAAA record, then SMTP trys the delivery to that IP
        # # DANE allows TLSA records for such domains https://datatracker.ietf.org/doc/html/rfc7672#section-2.2.2
        # # The code below detects the, but couldn't find an instance where this is used in practice  
        # nonmxtlsaflag, nonmxtlsadetails = lookuptlsa(resolver, domain, 25, delimiter)
        # if nonmxtlsaflag == 1:
        #     print(f"{domain}: no MX, but TLSA ({nonmxtlsadetails})", file=sys.stderr)
    # DANE requires DNSSEC for MX lookup *and* TLSA for MX domain https://datatracker.ietf.org/doc/html/rfc7672#section-2.2.1
    daneflag = indicator(mxauth and mxtlsaflag)
    stsflag, stsdetails = lookupsts(resolver, domain, delimiter)
    print(f'{domain},{indicator(len(mxs))},{indicator(mxauth)},{mxtlsaflag},{daneflag},{stsflag},{indicator(daneflag or stsflag)},"{mxdetails}","{mxtlsadetails}","{stsdetails}"', flush=True)

def parse_args(resolver: dns.resolver.Resolver) -> argparse.Namespace:
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
    argparser.add_argument('-s', '--nameserver', type=str, action='append',
                           help='use custom nameserver, repeat to add multiple')
    argparser.add_argument('-d', '--delimiter', type=str, default='\\n',
                           help='delimiter string used to concatenate records (default: %(default)s)')
    opts = argparser.parse_args()
    opts.delimiter = bytes(opts.delimiter, 'utf-8').decode('unicode_escape') # https://docs.python.org/3/library/codecs.html#python-specific-encodings
    return opts

def configure_resolver(resolver: dns.resolver.Resolver, opts: argparse.Namespace):
    if opts.nameserver:
        resolver.nameservers = opts.nameserver
    resolver.timeout = opts.timeout
    resolver.lifetime = opts.lifetime
    resolver.retry_servfail = opts.retry
    resolver.set_flags(dns.flags.RD | dns.flags.AD) # RD recursion desired, AD authenticated data

if __name__ == '__main__':
    resolver = dns.resolver.Resolver()
    opts = parse_args(resolver)
    configure_resolver(resolver, opts)
    try:
        if opts.header:
            print("domain,has_mx,has_mxauth,has_mxtlsa,has_smtpdane,has_mtasts,has_any,mx_details,mxtlsa_details,mtasts_details")
        for domain in opts.domains:
            lookupdomain(resolver, domain, opts.delimiter)
    except KeyboardInterrupt:
        pass
