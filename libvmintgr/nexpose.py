import sys
import xml.etree.ElementTree as ET
import StringIO
import csv
import time
import datetime
import pytz
import urllib
import urllib2
import cookielib

sys.path.append('../../pnexpose')

import pnexpose
import debug
import vuln

cookiejar = None
nx_console_server = None
nx_console_port = None

class nexpose_connector(object):
    def __init__(self, server, port, user, pw):
        self.conn = pnexpose.nexposeClient(server, port, user, pw)
        self.sitelist = {}

def nexpose_consolelogin(server, port, user, pw):
    global nx_console_server
    global nx_console_port
    global cookiejar

    loginurl = 'https://%s:%d/login.html' % (server, port)
    vals = { 'nexposeccusername': user,
             'nexposeccpassword': pw,
             'loginRedir': '/home.jsp',
             'screenresolution': '1280x800' }

    nx_console_server = server
    nx_console_port = port

    cookiejar = cookielib.LWPCookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))
    urllib2.install_opener(opener)
    formdata = urllib.urlencode(vals)
    req = urllib2.Request(loginurl, formdata)
    resp = urllib2.urlopen(req)

    # XXX Handle a failed login here

def generate_report(scanner, repid):
    debug.printd('requesting generation of report %s' % repid)
    replist = scanner.conn.report_generate(repid)
    debug.printd('polling for completion, standby')
    replist = None
    while True:
        replist = report_list(scanner)
        if replist[repid]['status'] == 'Generated':
            debug.printd('report generation complete')
            break
        time.sleep(5)
    ret = nexpose_fetch_report(repid, replist[repid]['url'])
    return ret

def nexpose_parse_custom_authfail(buf):
    # This function operates on the following custom query associated with the
    # auth failure report:
    #
    # SELECT da.ip_address, da.host_name, os.name, critical_vulnerabilities,
    # severe_vulnerabilities, exploits, riskscore,
    # aggregated_credential_status_description   
    # FROM fact_asset    
    # JOIN dim_aggregated_credential_status USING(aggregated_credential_status_id)
    # JOIN dim_asset da USING(asset_id)
    # JOIN dim_operating_system os USING(operating_system_id)
    reader = csv.reader(StringIO.StringIO(buf))
    ret = []
    for i in reader:
        if i[0] == 'ip_address':
            continue
        newent = {}
        newent['ip'] = i[0]
        newent['hostname'] = i[1]
        if newent['hostname'] == '':
            newent['hostname'] = 'unknown'
        newent['os'] = i[2]
        newent['ncrit'] = i[3]
        newent['nsevere'] = i[4]
        newent['exploits'] = i[5]
        newent['riskscore'] = i[6]
        if i[7] == 'All credentials failed':
            newent['credstatus'] = 'FAIL'
        elif i[7] == 'N/A':
            newent['credstatus'] = 'NA'
        else:
            newent['credstatus'] = 'OK'
        ret.append(newent)
    return ret

def nexpose_fetch_report(repid, reploc):
    global cookiejar

    url = 'https://%s:%d/%s' % (nx_console_server, nx_console_port, reploc)

    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookiejar))
    urllib2.install_opener(opener)
    req = urllib2.Request(url, None)
    resp = urllib2.urlopen(req)
    return resp.read()

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
        idx = i[7].find('.')
        if idx > 0:
            dstr = i[7][:idx]
        else:
            dstr = i[7]
        dt = datetime.datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=pytz.UTC)
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

def report_list(scanner):
    debug.printd('requesting report list')
    replist = scanner.conn.report_listing()

    ret = {}
    root = ET.fromstring(replist)
    for s in root:
        if s.tag != 'ReportConfigSummary':
            continue
        newrep = {}
        newrep['name'] = s.attrib['name']
        newrep['id'] = s.attrib['cfg-id']
        newrep['last-generated'] = s.attrib['generated-on']
        newrep['status'] = s.attrib['status']
        if 'report-URI' in s.attrib:
            newrep['url'] = s.attrib['report-URI']
        else:
            newrep['url'] = None
        ret[newrep['id']] = newrep
    return ret

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
