# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import csv
import StringIO

import debug
import nexadhoc

# Given a group ID, return a list of scans that should be taken into
# consideration.
def scan_scope(scanner, gid):
    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return []

    squery = '''
    WITH applicable_assets AS (
    SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s
    )
    SELECT asset_id, scan_id
    FROM fact_asset_scan
    WHERE asset_id IN (SELECT asset_id FROM applicable_assets)
    ''' % gid

    buf = nexadhoc.nexpose_adhoc(scanner, squery, sites, api_version='1.4.0')
    ret = []
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if i == None or len(i) == 0:
            break
        if i[0] == 'asset_id':
            continue
        if i[1] == '':
            debug.printd('notice: no scan id for asset %s' % i[0])
            continue
        if i[1] not in ret:
            ret.append(i[1])
    return ret

def device_scope(scanner, gid):
    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return []

    squery = '''
    SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s
    ''' % gid

    buf = nexadhoc.nexpose_adhoc(scanner, squery, sites, api_version='1.4.0')
    ret = []
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if i == None or len(i) == 0:
            break
        if i[0] == 'asset_id':
            continue
        if i[0] not in ret:
            ret.append(i[0])
    return ret

def cs_abyi(scanner, gid, timestamp, scanscope, devicescope):
    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    squery = '''
    WITH applicable_assets AS (
    SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s
    ),
    asset_scan_map AS (
    SELECT asset_id, scanAsOf(asset_id, '%s') as scan_id
    FROM dim_asset
    WHERE asset_id IN (SELECT asset_id FROM applicable_assets)
    ),
    state_snapshot AS (
    SELECT asset_id, scan_id, vulnerability_id,
    round(dv.cvss_score::numeric, 2) AS cvss_score,
    date
    FROM fact_asset_scan_vulnerability_instance
    JOIN asset_scan_map USING (asset_id, scan_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    ),
    vuln_age AS (
    SELECT fasvi.asset_id, fasvi.vulnerability_id,
    MIN(fasvi.date) as earliest,
    ss.date AS latest
    FROM fact_asset_scan_vulnerability_instance as fasvi
    JOIN state_snapshot AS ss USING (asset_id, vulnerability_id)
    GROUP BY fasvi.asset_id, fasvi.vulnerability_id, ss.date
    )
    SELECT * FROM vuln_age
    ''' % (gid, timestamp)

    ret = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2',
        scan_ids=scanscope)
    print ret

def cs_vbyi(scanner, gid, timestamp, scanscope, devicescope):
    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    squery = '''
    WITH applicable_assets AS (
    SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s
    ),
    asset_scan_map AS (
    SELECT asset_id, scanAsOf(asset_id, '%s') as scan_id
    FROM dim_asset
    WHERE asset_id IN (SELECT asset_id FROM applicable_assets)
    ),
    state_snapshot AS (
    SELECT asset_id, scan_id, vulnerability_id,
    round(dv.cvss_score::numeric, 2) AS cvss_score
    FROM fact_asset_scan_vulnerability_instance
    JOIN asset_scan_map USING (asset_id, scan_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    )
    SELECT
    SUM(CASE WHEN cvss_score >= 9 THEN 1 ELSE 0 END) AS "maximum",
    SUM(CASE WHEN (cvss_score >= 7 AND cvss_score < 9) THEN 1 ELSE 0 END) AS
    "high",
    SUM(CASE WHEN cvss_score < 7 THEN 1 ELSE 0 END) AS "mediumlow",
    COUNT(*) as "total"
    FROM state_snapshot
    ''' % (gid, timestamp)

    ret = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2',
     scan_ids=scanscope)
    print ret

def current_state_summary(scanner, gid, window_end, scanscope, devicescope):
    cs_vbyi(scanner, gid, window_end, scanscope, devicescope)
    cs_abyi(scanner, gid, window_end, scanscope, devicescope)

    return None
