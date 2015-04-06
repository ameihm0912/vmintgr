#!/usr/bin/python2
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import getopt
import re

exlist = []

def usage():
    sys.stdout.write('usage: hfuzz-add.py [-hi] [-x path] vulnauto hfuzzout ' \
        'groupmatch\n')

def excheck(buf):
    for x in exlist:
        if x.match(buf):
            return True
    return False

def load_expath(path):
    fd = open(path, 'r')
    while True:
        buf = fd.readline()
        if buf == None or buf == '':
            break
        buf = buf.strip()
        exlist.append(re.compile(buf))
    fd.close()

def domain():
    tag = 'namematch ='

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hix:')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
        sys.exit(1)
    for o, a in opts:
        if o == '-h':
            usage()
            sys.exit(0)
        elif o == '-i':
            tag = 'ipmatch ='
        elif o == '-x':
            load_expath(a)

    if len(args) != 3:
        usage()
        sys.exit(0)

    vaf = args[0]
    hfo = args[1]
    grp = args[2]

    fd = open(vaf, 'r')
    buf = fd.readlines()
    fd.close()

    hfd = open(hfo, 'r')

    idx = 0
    for i in buf:
        if tag in i:
            break
        idx += 1

    firstent = False
    s = buf[idx].split()
    if len(s) == 2:
        firstent = True
    else:
        idx += 1
        for i in buf[idx:]:
            if '=' in i:
                break
            idx += 1

    autoadd = False
    while True:
        tmp = hfd.readline()
        if tmp == None or tmp == '':
            break
        el = tmp.strip().split()
        if len(el) != 4:
            continue
        if el[2] != grp:
            continue
        if excheck(el[0]):
            continue
        if firstent:
            buf[idx] = '%s #AUTOADD\n' % tag
            autoadd = True
            idx += 1
            buf.insert(idx, '\t%s\n' % el[0])
            firstent = False
        else:
            if not autoadd:
                buf.insert(idx, '\t#AUTOADD\n')
                idx += 1
                autoadd = True
            buf.insert(idx, '\t%s\n' % el[0])

    sys.stdout.write(''.join(buf))

if __name__ == '__main__':
    domain()

sys.exit(0)
