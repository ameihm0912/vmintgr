# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import csv
import StringIO

import debug
import nexadhoc

def aid_where(assetset):
    ws = None
    for i in assetset:
        if ws == None:
            ws = '(asset_id = %s' % i
        else:
            ws += ' OR asset_id = %s' % i
    ws += ')'
    return ws

def applicable_scans(scanner, assetset):
    ret = []
    for i in assetset:
        buf = assetset[i]
        if buf['start'][0] not in ret:
            ret.append(buf['start'][0])
        if buf['end'][0] not in ret:
            ret.append(buf['end'][0])
    return ret

def current_state_summary(scanner, assetset, window_end):
    buf = vulns_at_period(scanner, assetset, window_end)
    print buf

def vulns_at_period(scanner, assetset, period):
    squery = '''
    WITH asset_scan_map AS (
    SELECT asset_id, scanAsOf(asset_id, '%s') as scan_id
    FROM dim_asset
    WHERE %s
    )
    SELECT asset_id, scan_id, vulnerability_id FROM
    fact_asset_scan_vulnerability_finding
    WHERE scan_id IN (SELECT scan_id FROM asset_scan_map) AND
    asset_id IN (SELECT asset_id FROM asset_scan_map)
    ''' % (period, aid_where(assetset))

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    appscans = applicable_scans(scanner, assetset)

    ret = nexadhoc.nexpose_adhoc(scanner, squery, sites, \
        api_version='1.4.0', scan_ids=appscans)
    return ret

def vuln_extract_asset_set(scanner, assetset):
    scans = []
    for i in assetset:
        buf = assetset[i]
        if buf['start'][0] not in scans:
            scans.append(buf['start'][0])
        if buf['end'][0] not in scans:
            scans.append(buf['end'][0])
    debug.printd('need data from %d scans' % len(scans))
    ret = {}
    for i in scans:
        vuln_scan_extract(scanner, assetset, ret, i)

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
