# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import hashlib

import debug

adhoc_cache = False

def nexpose_adhoc_cache(flag):
    global adhoc_cache
    adhoc_cache = flag

def get_cache_key(s):
    return hashlib.md5(s).hexdigest()

def get_cache(s):
    try:
        fd = open(s, 'r')
    except IOError:
        return False, None
    ret = fd.read()
    fd.close()
    return True, ret

def write_cache(cachefn, s):
    fd = open(cachefn, 'w')
    fd.write(s)
    fd.close()

def nexpose_adhoc(scanner, squery, sites, api_version=None, cache_key=None):
    if cache_key == None:
        cache_key = get_cache_key(squery)
    cachefn = './adhoc.' + cache_key

    if adhoc_cache:
        debug.printd('using adhoc cache %s' % cachefn)
        flag, data = get_cache(cachefn)
        if flag:
            debug.printd('cache hit, returning data')
            return data
        debug.printd('cache not found, will populate this round')

    ret = None
    if api_version != None:
        ret = scanner.conn.adhoc_report(squery, sites,
            api_version=api_version)
    else:
        ret = scanner.conn.adhoc_report(squery, sites)
    if adhoc_cache:
        debug.printd('writing cache to %s' % cachefn)
        write_cache(cachefn, ret)

    return ret
