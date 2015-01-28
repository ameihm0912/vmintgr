#!/usr/bin/python2
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
import re
import getopt

from fuzzywuzzy import fuzz
from fuzzywuzzy import process
from fuzzywuzzy import utils

HOST_TRAIL_TRIM = 3

def fuzz_host_trim(hostname):
    el = hostname.strip().split('.')
    if len(el) == 1:
        return el[0]
    if len(el) <= HOST_TRAIL_TRIM:
        return None
    return ' '.join(el[:-HOST_TRAIL_TRIM])

def fuzz_match_host(hostname, hints):
    bmgrp = None
    bment = None
    bmscore = 0
    fullhost = hostname
    hostname = fuzz_host_trim(hostname)
    for hf in hints:
        cand = hints[hf]
        r = process.extract(hostname, cand, limit=2)
        for i in r:
            if i[1] > bmscore:
                bmscore = i[1]
                bmgrp = hf
                bment = i[2]
    if bmscore > 85:
        return bmgrp, bment
    return None, None

def fuzz_match_load(path):
    ret = {}
    dirlist = os.listdir(path)
    for i in dirlist:
        fd = open(os.path.join(path, i), 'r')
        if i not in ret:
            ret[i] = {}
        while True:
            buf = fd.readline()
            if buf == None or buf == '':
                break
            buf = buf.strip()
            trimbuf = fuzz_host_trim(buf)
            if trimbuf != None:
                ret[i][buf] = trimbuf
        fd.close()
    return ret

def domain():
    if len(sys.argv) != 3:
        sys.stdout.write('usage: hfuzz.py hostnames hintsdir\n')
        sys.exit(0)
    hints = fuzz_match_load(sys.argv[2])
    fd = open(sys.argv[1], 'r')
    proc = 0
    hit = 0
    lncnt = len(fd.readlines())
    fd.seek(0)
    while True:
        buf = fd.readline()
        if buf == None or buf == '':
            break
        h = buf.strip()
        grp, ent = fuzz_match_host(h, hints)
        proc += 1
        if grp != None:
            hit += 1
            sys.stdout.write('%s -> %s (%s)\n' % (h, grp, ent))
        else:
            sys.stdout.write('%s ?\n' % h)
        if proc % 40 == 0:
            sys.stderr.write('%d processed, %d hits - %.2f%% complete\n' % \
                (proc, hit, (float(proc) / float(lncnt)) * 100))
    fd.close()

if __name__ == '__main__':
    domain()

sys.exit(0)
