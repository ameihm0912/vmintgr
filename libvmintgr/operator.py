# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os

import debug

opermap = {}

def addr_get_operator(ipaddr):
    for i in opermap:
        if 'addr' not in opermap[i]:
            continue
        for a in opermap[i]['addr']:
            if a == ipaddr:
                return i
    return 'unknown'

def load_operator_addr(path, opername):
    debug.printd('loading operator address data from %s' % path)
    opermap[opername]['addr'] = []
    fd = open(path, 'r')
    for i in fd.readlines():
        opermap[opername]['addr'].append(i.strip())
    fd.close()

def load_opdir(path, opername):
    opermap[opername] = {}
    f = os.path.join(path, 'addr')
    if os.path.isfile(f):
        load_operator_addr(f, opername)

def load_operator(operdir):
    dirlist = os.listdir(operdir)
    for i in dirlist:
        load_opdir(os.path.join(operdir, i), i)
