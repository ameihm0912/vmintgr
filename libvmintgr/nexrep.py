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
        self.current_statestat = {}
        self.current_compliance = None
        self.current_compstat = {}

        self.previous_states = []
        self.previous_statestat = []
        self.previous_compliance = []
        self.previous_compstat = []

        self.hist = None

def risk_summary(vmd):
    pass

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

def vmd_compliance(vlist):
    # Create a compliance element for each finding in the list. failvuln
    # is used to point to the associated issue here, and the failed flag
    # is set on any failures.
    ret = []
    failcnt = 0
    for a in vlist:
        for v in vlist[a]:
            newcomp = vuln.ComplianceElement()
            newcomp.failed = False
            newcomp.failvuln = v
            for level in vuln.ComplianceLevels.ORDERING:
                if v.cvss >= vuln.ComplianceLevels.FLOOR[level] and \
                    v.age_days > vuln.ComplianceLevels.LEVELS[level]:
                    newcomp.failed = True
                    failcnt += 1
                    break
            ret.append(newcomp)
    debug.printd('vmd_compliance returning %d elements (%d failed)' \
        % (len(ret), failcnt))
    return ret

def compliance_count(compset):
    ret = {}

    ret['maximum'] = {'pass': 0, 'fail': 0}
    ret['high'] = {'pass': 0, 'fail': 0}
    ret['mediumlow'] = {'pass': 0, 'fail': 0}
    for i in compset:
        if i.failvuln.cvss >= 9:
            tag = 'maximum'
        elif i.failvuln.cvss >= 7 and i.failvuln.cvss < 9:
            tag = 'high'
        else:
            tag = 'mediumlow'
        if i.failed:
            ret[tag]['fail'] += 1
        else:
            ret[tag]['pass'] += 1
    return ret

def age_average(vulnset):
    ret = {}
    setbuf = {'maximum': [], 'high': [], 'mediumlow': []}
    if len(vulnset) == 0:
        return None
    for a in vulnset:
        for v in vulnset[a]:
            if v.cvss >= 9:
                avgset = 'maximum'
            elif v.cvss >= 7 and v.cvss < 9:
                avgset = 'high'
            else:
                avgset = 'mediumlow'
            setbuf[avgset].append(v.age_days)
    ret['maximum'] = reduce(lambda x, y: x + y, setbuf['maximum']) \
        / len(setbuf['maximum'])
    ret['high'] = reduce(lambda x, y: x + y, setbuf['high']) \
        / len(setbuf['high'])
    ret['mediumlow'] = reduce(lambda x, y: x + y, setbuf['mediumlow']) \
        / len(setbuf['mediumlow'])
    return ret

def host_impact(vulnset):
    ret = []
    for a in vulnset:
        suma = 0
        for v in vulnset[a]:
            suma += v.cvss
        ret.append({'assetid': a, 'score': suma})
    ret = sorted(ret, key=lambda k: k['score'], reverse=True)
    return ret

def vuln_impact(vulnset):
    ret = []
    vbuf = {}
    for a in vulnset:
        for v in vulnset[a]:
            if v.vid not in vbuf:
                vbuf[v.vid] = {'count': 0, 'score': 0, 'age_set': []}
            vbuf[v.vid]['count'] += 1
            vbuf[v.vid]['score'] += v.cvss
            vbuf[v.vid]['age_set'].append(v.age_days)
    for i in vbuf:
        v = vbuf[i]
        v['ageavg'] = reduce(lambda x, y: x + y, v['age_set']) \
            / len(v['age_set'])
        del v['age_set']
    for v in vbuf:
        new = vbuf[v]
        new['vid'] = v
        ret.append(new)
    ret = sorted(ret, key=lambda k: k['score'], reverse=True)
    return ret

def node_impact_count(vulnset):
    ret = {'maximum': 0, 'high': 0, 'mediumlow': 0}
    for a in vulnset:
        maxcvss = 0
        for v in vulnset[a]:
            if v.cvss > maxcvss:
                maxcvss = v.cvss
        if maxcvss >= 9:
            cntset = 'maximum'
        elif maxcvss >= 7 and maxcvss < 9:
            cntset = 'high'
        else:
            cntset = 'mediumlow'
        if maxcvss > 0:
            ret[cntset] += 1
    return ret

def find_vid(vid, vbuf):
    for v in vbuf:
        if v.vid == vid:
            return v

def find_resolved(vmd):
    if len(vmd.previous_states) == 0:
        return []

    cur = vmd.current_state
    old = vmd.previous_states[0]

    vbuf = {}
    for a in old:
        for v in old[a]:
            if v.vid not in vbuf:
                vbuf[v.vid] = {'vid': v.vid, 'count': 0, 'resolved': 0}
            # See if the issue is found in the current window, if not it's
            # marked as resolved.
            if a not in cur:
                vbuf[v.vid]['resolved'] += 1
                continue
            tmpv = find_vid(v.vid, cur[a])
            if tmpv == None:
                vbuf[v.vid]['resolved'] += 1
                continue
            vbuf[v.vid]['count'] += 1
    ret = []
    for v in vbuf:
        new = vbuf[v]
        new['vid'] = v
        ret.append(new)
    return ret

def dataset_statestat(vmd):
    debug.printd('summarizing state statistics...')
    vmd.current_statestat['ageavg'] = \
        age_average(vmd.current_state)
    vmd.current_statestat['nodeimpact'] = \
        node_impact_count(vmd.current_state)
    vmd.current_statestat['hostimpact'] = \
        host_impact(vmd.current_state)
    vmd.current_statestat['vulnimpact'] = \
        vuln_impact(vmd.current_state)
    vmd.current_statestat['resolved'] = \
        find_resolved(vmd)

    for i in vmd.previous_states:
        newval = {}
        newval['ageavg'] = age_average(i)
        newval['nodeimpact'] = node_impact_count(i)
        newval['hostimpact'] = host_impact(i)
        newval['vulnimpact'] = vuln_impact(i)
        vmd.previous_statestat.append(newval)

def dataset_compstat(vmd):
    debug.printd('summarizing compliance statistics...')
    vmd.current_compstat['passfailcount'] = \
        compliance_count(vmd.current_compliance)

    for i in vmd.previous_compliance:
        newval = {}
        newval['passfailcount'] = compliance_count(i)
        vmd.previous_compstat.append(newval)

def dataset_compliance(vmd):
    debug.printd('calculating current state compliance...')
    vmd.current_compliance = vmd_compliance(vmd.current_state)
    debug.printd('calculating previous state compliance...')
    for i in vmd.previous_states:
        vmd.previous_compliance.append(vmd_compliance(i))

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

    dataset_statestat(vmd)

    dataset_compliance(vmd)
    dataset_compstat(vmd)

    return vmd

