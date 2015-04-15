#!/usr/bin/python

# Small script for formatting output from vmintgr host group vuln list
# into a summary

import sys

hosts = {}
while True:
    buf = sys.stdin.readline()
    if buf == '':
        break
    host, label = list(buf.strip().split()[i] for i in [0, 5])

    if host not in hosts:
        hosts[host] = {}

    if label not in hosts[host]:
        hosts[host][label] = 1
    else:
        hosts[host][label] += 1

sys.stdout.write('%s%s%s%s\n' % \
    ('host'.ljust(40), 'medlow'.ljust(7), 'high'.ljust(5), 'max'.ljust(4)))

for x in hosts:
    hent = hosts[x]
    if 'maximum' in hent:
        nmax = hent['maximum']
    else:
        nmax = 0
    nhigh = hent['high']
    nlow = hent['mediumlow']
    sys.stdout.write('%s%s%s%s\n' % \
        (x.ljust(40), str(nlow).ljust(7), str(nhigh).ljust(5), \
        str(nmax).ljust(4)))

sys.exit(0)
