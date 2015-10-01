# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import json
import debug
import pyservicelib

serviceapi_enabled = False

def serviceapi_init(apihost, apicert):
    global serviceapi_enabled
    debug.printd('initializing integration with service api')
    if apicert == None:
        pyservicelib.config.sslverify = False
    else:
        pyservicelib.config.sslverify = apicert
    pyservicelib.config.apihost = apihost
    serviceapi_enabled = True

def serviceapi_vulnlist(vlist):
    if not serviceapi_enabled:
        return vlist
    oplist = []
    for x in vlist:
        oplist.append(json.loads(x))
    debug.printd('preparing query for serviceapi service lookup (vulnerabilities)')
    s = pyservicelib.Search()
    havehosts = []
    for x in oplist:
        hn = x['asset']['hostname']
        if len(hn) == 0:
            continue
        if hn in havehosts:
            continue
        s.add_host(hn, confidence=90)
        havehosts.append(hn)
    s.execute()
    for x in oplist:
        if len(x['asset']['hostname']) == 0:
            continue
        sres = s.result_host(x['asset']['hostname'])
        if sres == None:
            continue
        x['service'] = sres
    return [json.dumps(x) for x in oplist]

def serviceapi_complist(clist):
    if not serviceapi_enabled:
        return clist
    oplist = []
    for x in clist:
        oplist.append(json.loads(x))
    debug.printd('preparing query for serviceapi service lookup (compliance)')
    s = pyservicelib.Search()
    havehosts = []
    for x in oplist:
        # XXX As this data originates from MIG we should always have a valid
        # hostname field here, but check anyway.
        hn = x['target']
        if len(hn) == 0:
            continue
        if hn in havehosts:
            continue
        s.add_host(hn, confidence=90)
        havehosts.append(hn)
    s.execute()
    for x in oplist:
        if len(x['target']) == 0:
            continue
        sres = s.result_host(x['target'])
        if sres == None:
            continue
        x['service'] = sres
    return [json.dumps(x) for x in oplist]
