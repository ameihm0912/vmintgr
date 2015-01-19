#!/usr/bin/python2

import sys
import csv
import os

grps = {}

def usage():
    sys.stdout.write('usage: invconvert.py csvdump outdir\n')
    sys.exit(0)

def main():
    if len(sys.argv) != 3:
        usage()
    fd = open(sys.argv[1], 'r')
    rdr = csv.reader(fd)
    for r in rdr:
        if len(r) < 8:
            continue
        if r[2] == 'allocation':
            continue
        if r[4] != 'production' and r[4] != 'building':
            continue
        grpname = r[2].lower()
        if grpname == None:
            grpname = 'default'
        if r[7] == None:
            raise Exception('asset has no hostname')

        # Ignore anything that probably isn't an FQDN that is relevant
        sfx = r[7].split('.')
        if sfx[-1].lower() != 'com' and sfx[-1].lower() != 'net' and \
                sfx[-1].lower() != 'org':
            continue

        if grpname not in grps:
            grps[grpname] = []
        grps[grpname].append(r[7])
    fd.close()
    for i in grps:
        cnt = len(grps[i])
        fname = os.path.join(sys.argv[2], i.replace(' ', '_') + '.conf')
        sys.stdout.write('writing %s - %d assets\n' % (fname, cnt))
        fd = open(fname, 'w')
        for j in grps[i]:
            fd.write('%s\n' % j)
        fd.close()

if __name__ == '__main__':
    main()

sys.exit(0)
