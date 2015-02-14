# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import csv
import StringIO
import datetime
import pytz

import debug
import vuln
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
    ss.date AS latest,
    (CASE WHEN cvss_score >= 9 THEN 'maximum'
    WHEN (cvss_score >= 7 AND cvss_score < 9) THEN 'high'
    ELSE 'mediumlow' END) as impact
    FROM fact_asset_scan_vulnerability_instance as fasvi
    JOIN state_snapshot AS ss USING (asset_id, vulnerability_id)
    GROUP BY fasvi.asset_id, fasvi.vulnerability_id, ss.date,
    ss.cvss_score
    )
    SELECT
    impact,
    AVG(EXTRACT(EPOCH FROM (latest - earliest)))
    FROM vuln_age GROUP BY impact
    ''' % (gid, timestamp)

    ret = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2',
        scan_ids=scanscope, device_ids=devicescope)
    print ret

def vulns_at_time(scanner, gid, timestamp, scanscope, devicescope):
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
    current_state_snapshot AS (
    SELECT
    fasvf.asset_id, da.ip_address, da.host_name,
    fasvf.date AS discovered_date,
    fasvf.vulnerability_id,
    dv.title AS vulnerability,
    round(dv.cvss_score::numeric, 2) AS cvss_score
    FROM fact_asset_scan_vulnerability_finding fasvf
    JOIN dim_asset da USING (asset_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    JOIN asset_scan_map USING (asset_id, scan_id)
    ),
    issue_age AS (
    SELECT
    fasvf.asset_id, fasvf.vulnerability_id,
    MIN(fasvf.date) as earliest
    FROM fact_asset_scan_vulnerability_finding fasvf
    JOIN current_state_snapshot css USING (asset_id, vulnerability_id)
    GROUP BY asset_id, vulnerability_id
    )
    SELECT asset_id, ip_address, host_name, discovered_date,
    vulnerability_id, vulnerability, cvss_score,
    iage.earliest,
    EXTRACT(EPOCH FROM (discovered_date - iage.earliest))
    FROM current_state_snapshot
    JOIN issue_age iage USING (asset_id, vulnerability_id)
    ''' % (gid, timestamp)

    ret = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2',
     scan_ids=scanscope, device_ids=devicescope)
    reader = csv.reader(StringIO.StringIO(ret))
    vulnret = {}
    cnt = 0
    for i in reader:
        if i == None or len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        newvuln = vuln.vulnerability()
        newvuln.assetid = int(i[0])
        newvuln.ipaddr = i[1]
        newvuln.hostname = i[2]

        idx = i[3].find('.')
        if idx > 0:
            dstr = i[3][:idx]
        else:
            dstr = i[3]
        dt = datetime.datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=pytz.UTC)
        newvuln.discovered_date = dt

        newvuln.vid = i[4]
        newvuln.title = i[5]
        newvuln.cvss = float(i[6])
        newvuln.age_days = float(i[8]) / 60 / 60 / 24

        if newvuln.assetid not in vulnret:
            vulnret[newvuln.assetid] = []
        vulnret[newvuln.assetid].append(newvuln)
        cnt += 1

    debug.printd('vulns_at_time: %s: returning %d issues for %d assets' % \
        (timestamp, cnt, len(vulnret.keys())))
    return vulnret

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
     scan_ids=scanscope, device_ids=devicescope)
    print ret

def current_state_summary(scanner, gid, window_end, scanscope, devicescope):
    #cs_vbyi(scanner, gid, window_end, scanscope, devicescope)
    #cs_abyi(scanner, gid, window_end, scanscope, devicescope)
    vulns_at_time(scanner, gid, window_end, scanscope, devicescope)

    return None
