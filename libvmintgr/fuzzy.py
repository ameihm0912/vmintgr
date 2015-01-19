import os
import re

from fuzzywuzzy import fuzz
from fuzzywuzzy import process
from fuzzywuzzy import utils

import debug

HOST_TRAIL_TRIM = 3

def fuzzy_host_trim(hostname):
    el = hostname.strip().split('.')
    if len(el) <= 3:
        return None
    return ' '.join(el[:-3])

def fuzzy_match_host(hostname, hints):
    bmgrp = None
    bment = None
    bmscore = 0
    fullhost = hostname
    hostname = fuzzy_host_trim(hostname)
    debug.printd('trying to match %s (%s)' % (fullhost, hostname))
    for hf in hints:
        cand = process.extract(hostname, hints[hf], limit=2)
        for r in cand:
            if r[1] > bmscore:
                bmscore = r[1]
                bmgrp = hf
                bment = r[0]
    if bmscore > 85:
        debug.printd('using %s [%s] %d' % (bmgrp, bment, bmscore))
        return bmgrp, bment
    debug.printd('no decent match found')
    return None, None

def fuzzy_match_load(path):
    ret = {}
    debug.printd('loading fuzzy hint information...')
    dirlist = os.listdir(path)
    for i in dirlist:
        fd = open(os.path.join(path, i), 'r')
        if i not in ret:
            ret[i] = []
        while True:
            buf = fd.readline()
            if buf == None or buf == '':
                break
            buf = fuzzy_host_trim(buf)
            if buf != None:
                ret[i].append(buf)
        fd.close()
    cnt = 0
    for i in ret:
        cnt += len(ret[i])
    debug.printd('loaded %d fuzzy hint entries' % cnt)
    return ret
