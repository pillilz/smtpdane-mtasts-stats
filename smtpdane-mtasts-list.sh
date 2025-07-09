#!/bin/bash
smtpdane-mtasts-lookup.py -H
sort -u "$@" | xargs --max-args 100 --max-procs 100 smtpdane-mtasts-lookup.py --delimiter '|' --flush | sort
#sort -u "$@" | xargs smtpdane-mtasts-lookup.py --delimiter '|' --flush #| sort