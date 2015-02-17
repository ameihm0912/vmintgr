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

device_filter = None

class VMDataSet(object):
    def __init__(self):
        self.current_state = None
        self.previous_states = []
        self.hist = None

def populate_query_filters(scanner, gid):
    populate_device_filter(scanner, gid)

def populate_device_filter(scanner, gid):
    global device_filter

    squery = '''
    SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s
    ''' % gid

    debug.printd('populating device filter...')
    buf = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2')
    device_filter = []
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if i == None or len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        if i[0] not in device_filter:
            device_filter.append(i[0])
    debug.printd('%d devices in device filter' % len(device_filter))

def vulns_over_time(scanner, gid, start, end):
    squery = '''
    WITH applicable_assets AS (
    SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s
    ),
    applicable_scans AS (
    SELECT asset_id, scan_id
    FROM fact_asset_scan
    WHERE (scan_finished >= '%s') AND
    (scan_finished <= '%s') AND
    asset_id IN (SELECT asset_id FROM applicable_assets)
    ),
    all_findings AS (
    SELECT fasvf.asset_id, da.ip_address, da.host_name,
    MIN(fasvf.date) as first_seen,
    MAX(fasvf.date) as last_seen, fasvf.vulnerability_id,
    dv.title AS vulnerability,
    round(dv.cvss_score::numeric, 2) AS cvss_score
    FROM fact_asset_scan_vulnerability_finding fasvf
    JOIN dim_asset da USING (asset_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    JOIN applicable_scans USING (asset_id, scan_id)
    GROUP BY asset_id, ip_address, host_name, vulnerability_id,
    vulnerability, cvss_score
    )
    SELECT * FROM all_findings
    ''' % (gid, start, end)

    ret = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2',
        device_ids=device_filter)
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
        newvuln.vid = i[5]
        newvuln.title = i[6]
        newvuln.cvss = float(i[7])


        idx = i[3].find('.')
        if idx > 0:
            dstr = i[3][:idx]
        else:
            dstr = i[3]
        dt = datetime.datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=pytz.UTC)
        first_date = dt

        idx = i[4].find('.')
        if idx > 0:
            dstr = i[4][:idx]
        else:
            dstr = i[4]
        dt = datetime.datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=pytz.UTC)
        last_date = dt

        if newvuln.assetid not in vulnret:
            vulnret[newvuln.assetid] = {}
        newfinding = {}
        newfinding['vulnerability'] = newvuln
        newfinding['first_date'] = first_date
        newfinding['last_date'] = last_date
        vulnret[newvuln.assetid][newvuln.vid] = newfinding
        cnt += 1

    debug.printd('vulns_over_time: returning %d issues from %s to %s' % \
        (cnt, start, end))
    return vulnret

def vulns_at_time(scanner, gid, timestamp):
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
        device_ids=device_filter)
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

def dataset_fetch(scanner, gid, window_start, window_end):
    vmd = VMDataSet()

    # Export current state information for the asset group.
    debug.printd('fetching vulnerability data for end of window')
    vmd.current_state = vulns_at_time(scanner, gid, window_end)

    wndsize = window_end - window_start
    for i in range(3):
        wnd_end = window_end - ((i + 1) * wndsize)
        debug.printd('fetching previous window data (%s)' % wnd_end)
        vmd.previous_states.append(vulns_at_time(scanner, gid, wnd_end))

    # Grab historical information. We apply 3 extra windows of the specified
    # size to the query (e.g., if the reporting window is one month we will
    # query back 3 months. This is primarily to gain enough information to
    # identify trends.
    trend_start = window_start - ((window_end - window_start) * 3)
    debug.printd('fetching historical findings from %s to %s' % \
        (trend_start, window_end))
    vmd.hist = vulns_over_time(scanner, gid, trend_start, window_end)

    return vmd

