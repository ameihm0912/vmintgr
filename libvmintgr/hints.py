# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
import csv
import StringIO
import cPickle
import time
import json
import calendar
import debug
import nexpose
import nexadhoc

def hints_block(scanner, whereclause):
    squery = '''
    SELECT asset_id, da.ip_address, da.host_name,
    da.mac_address, dos.description as operating_system,
    dht.description,
    dos.cpe
    FROM dim_asset da
    JOIN dim_operating_system dos USING (operating_system_id)
    JOIN dim_host_type dht USING (host_type_id)
    %s
    ''' % whereclause

    buf = nexadhoc.nexpose_adhoc(scanner, squery, [],
        api_version='1.3.2')

    ret = {}
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        newent = {}
        newent['summary'] = 'vmintgr asset hint'

        newdet = {}
        newdet['nexassetid'] = i[0]

        newdet['ipv4'] = []
        newdet['ipv4'].append(i[1])

        newdet['ipv6'] = []

        if len(i[2]) > 0:
            newdet['hostname'] = i[2]

        newdet['macaddress'] = []
        if len(i[3]) > 0:
            newdet['macaddress'].append(i[3])

        if len(i[4]) > 0 and i[4] != 'Unknown':
            newdet['ident'] = i[4]
        if len(i[5]) > 0 and i[5] != 'Unknown':
            newdet['hosttype'] = i[5]
        if len(i[6]) > 0 and i[6] != 'Unknown':
            newdet['cpe'] = i[6]
        newent['details'] = newdet
        ret[i[0]] = newent

    debug.printd('extracting asset ip aliases')
    squery = '''
    SELECT asset_id, ip_address, type
    FROM dim_asset_ip_address
    '''

    buf = nexadhoc.nexpose_adhoc(scanner, squery, [],
        api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        if i[0] not in ret:
            continue
        t = i[2]
        if t == 'IPv4':
            if i[1] not in ret[i[0]]['details']['ipv4']:
                debug.printd('adding another ip address for %s' % i[0])
                ret[i[0]]['details']['ipv4'].append(i[1])
        elif t == 'IPv6':
            if i[1] not in ret[i[0]]['details']['ipv6']:
                debug.printd('adding another ip address for %s' % i[0])
                ret[i[0]]['details']['ipv6'].append(i[1])

    debug.printd('extracting asset mac aliases')
    squery = '''
    SELECT asset_id, mac_address
    FROM dim_asset_mac_address
    '''

    buf = nexadhoc.nexpose_adhoc(scanner, squery, [],
        api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        if i[0] not in ret:
            continue
        if i[1] not in ret[i[0]]['details']['macaddress']:
            debug.printd('adding another mac address for %s' % i[0])
            ret[i[0]]['details']['macaddress'].append(i[1])

    debug.printd('extracting asset software')
    squery = '''
    SELECT da.asset_id, ds.name, ds.version
    FROM dim_asset da
    JOIN dim_asset_software USING (asset_id)
    JOIN dim_software ds USING (software_id)
    '''

    buf = nexadhoc.nexpose_adhoc(scanner, squery, [],
        api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        if i[0] not in ret:
            continue
        if 'software' not in ret[i[0]]['details']:
            ret[i[0]]['details']['software'] = []
        ret[i[0]]['details']['software'].append('%s-%s' % \
            (i[1], i[2]))

    return ret

def write_hint_escalations(hlist, escdir):
    fname = 'hints-%d-%d.dat' % (int(calendar.timegm(time.gmtime())),
        os.getpid())
    outfile = os.path.join(escdir, fname)
    tmpoutfile = outfile + '.tmp'
    debug.printd('writing hint escalations to %s' % outfile)

    fd = open(tmpoutfile, 'w')
    cPickle.dump(hlist, fd)
    fd.close()
    os.rename(tmpoutfile, outfile)

def escalate_hints(escdir, scanner, hintsflag, whereclause):
    if not hintsflag:
        return
    debug.printd('extracting asset hint data from database')
    hintblock = hints_block(scanner, whereclause)
    hlist = []
    for x in hintblock:
        hlist.append(json.dumps(hintblock[x]))
    write_hint_escalations(hlist, escdir)

