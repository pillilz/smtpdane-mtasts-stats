#!/usr/bin/python3

import sys
import csv
import matplotlib.pyplot as plt

with open(sys.argv[1]) as file:
    n = ndane = nsts = nany = nboth = nmxauth = 0
    csvreader = csv.reader(file)
    next(csvreader) # skip header
    for row in csvreader:
        # print(*row[0:5])
        mx, mxauth, mxtlsa, dane, sts, dane_or_sts = map(int, row[1:7])
        if not mx:
            continue
        ndane += dane
        nsts += sts
        nany += dane_or_sts
        nmxauth += mxauth
        if dane == 1 and sts == 1:
            nboth += 1
        n += 1
ndaneonly = ndane - nboth
nstsonly = nsts - nboth

print("Common mailservers")
print("mailservers dane_or_sts dane_or_sts% mx_auth mx_auth%")
print(f"{n} {nany} {nany/n:.1%} {nmxauth} {nmxauth/n:.1%}")
print("Common mailservers supporting dane or sts")
print("total daneonly stsonly both")
print(f"{nany} {ndaneonly} {nstsonly} {nboth}")
print("daneonly% stsonly% both%")
print(f"{ndaneonly/nany:.1%} {nstsonly/nany:.1%} {nboth/nany:.1%}")

def autopct(p, n):
    return f"{p:1.1f}% ({n*p/100:1.0f})"
    #return f"{n*p/100:1.0f}\n{p:1.1f}%"

if len(sys.argv) == 3:
    tab = plt.color_sequences["tab20c"]
    colors = [tab[i] for i in [4, 8]]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4), layout='constrained')
    fig.suptitle("2025-04", y=0.0, verticalalignment='bottom')
    #fig.subplots_adjust(wspace=.5)
    labels = ['not published', 'published']
    ax1.pie([n - nany, nany], autopct=lambda p: autopct(p, n), labels=labels, colors=colors, explode=[0, .2], startangle=360*nany/n/2)
    ax1.set_title("Email providers publishing SMTP TLS policies\n(SMTP DANE or MTA STS)")

    labels = ['SMTP DANE only', 'both standards', 'MTA STS only']
    colors = [tab[i] for i in [9, 8, 10]]
    ax2.pie([ndaneonly, nboth, nstsonly], autopct=lambda p: autopct(p, nany), colors=colors)
    ax2.set_title("SMTP TLS policy publication details\n(SMTP DANE and/or MTA STS)")
    ax2.legend(labels, title="Legend",
            loc="center left",
            bbox_to_anchor=(1, 0, 0.5, 1))
    #plt.show()
    plt.savefig(sys.argv[2])