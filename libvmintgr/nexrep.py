# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import csv
import StringIO

import debug
import nexadhoc

def vuln_extract_asset_set(scanner, assetset):
    pass

def asset_gid_scan_set(scanner, gid, window_start, window_end):
    squery = '''
    SELECT asset_id, scan_id, scan_finished
    FROM fact_asset_date('%s', '%s', INTERVAL '1 day')
    WHERE asset_id IN
    (SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s)
    ORDER BY scan_finished
    ''' % (window_start, window_end, gid)

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    debug.printd('building asset gid scan set')
    ret = nexadhoc.nexpose_adhoc(scanner, squery, sites, api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(ret))
    amap = {}
    for i in reader:
        if i[0] == 'asset_id':
            continue
        aid = i[0]
        if aid not in amap:
            amap[aid] = []
        amap[aid].append((i[1], i[2]))

    ret = {}
    # For each asset, we want to earliest and latest scan
    for i in amap:
        if i not in ret:
            ret[i] = {}
        ret[i]['start'] = amap[i][0]
        ret[i]['end'] = amap[i][-1]

    debug.printd('returning %d assets in asset set' % len(ret.keys()))
    return ret
