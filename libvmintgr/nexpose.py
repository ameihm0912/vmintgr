import sys
import xml.etree.ElementTree as ET
import StringIO
import csv

sys.path.append('../../pnexpose')

import pnexpose
import debug
import vuln

class nexpose_connector(object):
    def __init__(self, server, port, user, pw):
        self.conn = pnexpose.nexposeClient(server, port, user, pw)
        self.sitelist = {}

def vuln_extraction(scanner):
    squery = '''
    WITH 
    vuln_references AS ( 
        SELECT vulnerability_id, array_to_string(array_agg(reference), ', ')
        AS references 
        FROM dim_vulnerability 
        JOIN dim_vulnerability_reference USING (vulnerability_id) 
        GROUP BY vulnerability_id 
    ) 
    SELECT ds.name AS site, da.asset_id, da.ip_address,
    da.host_name, da.mac_address,  
    dv.title AS vulnerability, dvs.description AS status, favi.date
    AS discovered_date, 
    CASE WHEN favi.port = -1 THEN NULL ELSE favi.port END AS port, 
    dp.name AS protocol, dsvc.name AS service,
    round(dv.cvss_score::numeric, 2) AS cvss_score, vr.references, dv.exploits,
    dv.malware_kits
    FROM fact_asset_vulnerability_instance favi 
    JOIN dim_asset da USING (asset_id) 
    JOIN dim_vulnerability dv USING (vulnerability_id) 
    JOIN dim_site_asset dsa USING (asset_id) 
    JOIN dim_site ds USING (site_id) 
    JOIN dim_vulnerability_status dvs USING (status_id) 
    JOIN dim_protocol dp USING (protocol_id) 
    JOIN dim_service dsvc USING (service_id) 
    JOIN vuln_references vr USING (vulnerability_id) 
    ORDER BY ds.name, da.ip_address
    '''

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    vulndata = scanner.conn.adhoc_report(squery, sites)
    reader = csv.reader(StringIO.StringIO(vulndata))
    nvulns = 0
    linked = 0
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'site':
            continue
        nvulns += 1
        v = vuln.vulnerability()
        v.sitename = i[0]
        v.assetid = int(i[1])
        v.ipaddr = i[2]
        v.hostname = i[3]
        v.macaddr = i[4]
        v.title = i[5]
        v.discovered_date = i[7]
        v.cvss = float(i[11])

        linked += vuln_instance_link(v, scanner)

    debug.printd('%d vulnerabilities loaded' % nvulns)
    debug.printd('%d vulnerabilities linked' % linked)

def vuln_instance_link(v, scanner):
    ret = 0
    for s in scanner.sitelist.keys():
        for a in scanner.sitelist[s]['assets']:
            if a['id'] == v.assetid:
                a['vulns'].append(v)
                ret += 1
    return ret

def site_extraction(scanner):
    debug.printd('requesting site information')
    sitedata = scanner.conn.site_listing()
    root = ET.fromstring(sitedata)

    for s in root:
        siteinfo = {}
        siteinfo['name'] = s.attrib['name']
        siteinfo['id'] = s.attrib['id']
        siteinfo['assets'] = []
        scanner.sitelist[siteinfo['id']] = siteinfo
    debug.printd('read %d sites' % len(scanner.sitelist))

def asset_extraction(scanner):
    for sid in scanner.sitelist.keys():
        debug.printd('requesting devices for site %s (%s)' % \
            (scanner.sitelist[sid]['id'], scanner.sitelist[sid]['name']))
        devdata = scanner.conn.site_device_listing(sid)

        root = ET.fromstring(devdata)
        for s in root:
            if s.tag != 'SiteDevices':
                continue
            siteid = s.attrib['site-id']
            devlist = []
            for d in s:
                newdev = {}
                newdev['id'] = int(d.attrib['id'])
                newdev['address'] = d.attrib['address']
                newdev['vulns'] = []
                scanner.sitelist[sid]['assets'].append(newdev)
