#!/usr/bin/python3

import sys
import dns.resolver

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
        
def lookupmx(d):
    mxs = []
    try:
        answer = dns.resolver.resolve(d, "MX")
        # sort records by name to make mxs canonical
        records = sorted(answer, key=lambda r: r.exchange.to_unicode().lower())
        # sort preferred MX first
        records = sorted(records, key=lambda r: r.preference)
        # convert bytes to str
        mxs = [ r.exchange.to_unicode().lower() for r in records ]
        # remove invalid MX
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except (dns.resolver.LifetimeTimeout) as e:
        print(f";; {d}: {e}", file=sys.stderr)
    mxs = list(filter(validmx, mxs))
    return mxs

def lookupdane(d, mxs):
    for mx in mxs:
        try:
            answer = dns.resolver.resolve("_25._tcp." + mx, "TLSA")
            dane = "\n".join([ str(r) for r in answer ])
            return mx, dane
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except (dns.resolver.LifetimeTimeout) as e:
           print(f";; {d}: {e}", file=sys.stderr)
    return "", ""
    
def is_sts(s):
    return s.lower().startswith('v=stsv1')

def lookupsts(d):
    txts = []
    try:
        answer = dns.resolver.resolve("_mta-sts." + d, "TXT")
        # r.strings is a tuple of bytes as per RFC1035, which we concatenate
        txts = [ b''.join(r.strings).decode() for r in answer ]
        # filter for v=STSv1
        txts = [ t for t in txts if is_sts(t) ]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        pass
    except (dns.resolver.LifetimeTimeout) as e:
        print(f";; {d}: {e}", file=sys.stderr)
    if len(txts) > 1: print(f";; {d} has {len(txts)} MTA STS records", file=sys.stderr)
    return '\n'.join(txts)
def indicator(s):
    if (s):
        return 1
    else:
        return 0
    
def lookupdomain(d):
    mxs = lookupmx(d)
    if (len(mxs) == 0):
        pass #return
    _, dane = lookupdane(d, mxs)
    mx = "\n".join(mxs)
    sts = lookupsts(d)
    print(f'{d},{indicator(dane)},{indicator(sts)},{indicator(dane or sts)},"{mx}","{dane}","{sts}"')

try:
    if (len(sys.argv) == 1):
        print("domain,has_smtpdane,has_mtasts,has_any,mx_records,smtpdane_records,mtasts_records")
    for d in sys.argv[1:]:
        lookupdomain(d)
except KeyboardInterrupt:
    pass
