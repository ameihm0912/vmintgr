import sys
import os
import xml.etree.ElementTree as ET
import StringIO
import csv
import time
import datetime
import pytz
import tempfile
import urllib
import urllib2
import cookielib
import re
import netaddr

sys.path.append('../../pnexpose')

import pnexpose
import debug
import vuln
import exempt

cookiejar = None
nx_console_server = None
nx_console_port = None

class nexpose_connector(object):
    def __init__(self, server, port, user, pw):
        self.conn = pnexpose.nexposeClient(server, port, user, pw)
        self.sitelist = {}
        self.grouplist = {}

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

def nexpose_parse_custom_authfail(scanner, buf):
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
        # In some cases with a newly added host within a site that cannot
        # be authenticated to, Nexpose will put the site address in the
        # hostname column and leave the IP blank; if this happens just set
        # the IP address to the hostname, which is the IP anyway
        if newent['ip'] == '':
            if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                newent['hostname']):
                newent['ip'] = newent['hostname']

        sstr = None
        for s in scanner.sitelist.keys():
            siteent = scanner.sitelist[s]
            sn = siteent['name']
            for aent in siteent['assets']:
                if aent['address'] == newent['ip']:
                    if sstr == None:
                        sstr = siteent['name']
                    else:
                        sstr = sstr + ',' + siteent['name']
        if sstr == None:
            sstr = 'NA'
        newent['sites'] = sstr

        newent['os'] = i[2]
        newent['ncrit'] = i[3]
        newent['nsevere'] = i[4]
        newent['exploits'] = i[5]
        newent['riskscore'] = i[6]
        if exempt.ip_exempt(i[0]):
            newent['credstatus'] = 'EXEMPT'
        else:
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

def reptest(scanner):
    squery = '''
    SELECT da.ip_address, da.host_name, os.name, critical_vulnerabilities, severe_vulnerabilities,
    exploits, riskscore, aggregated_credential_status_description   
    FROM fact_asset    
    JOIN dim_aggregated_credential_status USING(aggregated_credential_status_id)
    JOIN dim_asset da USING(asset_id)
    JOIN dim_operating_system os USING(operating_system_id)
    '''

    debug.printd('adhoc report test')

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    ret = scanner.conn.adhoc_report(squery, sites, api_version='1.3.2')
    print ret
    sys.exit(0)

def add_asset_properties(scanner):
    squery = '''
    SELECT asset_id, ds.name AS site_name, da.ip_address, da.host_name,
    da.mac_address, dos.description AS operating_system, dht.description,
    dos.asset_type, dos.cpe FROM dim_asset da 
    JOIN dim_operating_system dos USING (operating_system_id) 
    JOIN dim_host_type dht USING (host_type_id) 
    JOIN dim_site_asset dsa USING (asset_id) 
    JOIN dim_site ds USING (site_id)
    '''

    debug.printd('requesting additional asset properties')

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    vulndata = scanner.conn.adhoc_report(squery, sites,
        api_version='1.3.2')

    reader = csv.reader(StringIO.StringIO(vulndata))
    atable = {}
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        atable[int(i[0])] = i[1:]

    for s in scanner.sitelist.keys():
        for a in scanner.sitelist[s]['assets']:
            if a['id'] not in atable.keys():
                a['hostname'] = ''
                a['macaddress'] = ''
                continue
            a['hostname'] = atable[a['id']][2]
            a['macaddress'] = atable[a['id']][3]

def vuln_age_days(v, agedata):
    # It's possible here that if the -r flag was used as the source for
    # vulnerabilities, and things were added to the file, we might not have
    # age data for the issue since that still comes from the server.
    #
    # In this case, return an age of 10 days.
    try:
        ret = agedata[v.assetid][int(v.vid)]
    except KeyError:
        return 10.0
    return ret

def vuln_get_age_data(scanner):
    squery = '''
    SELECT asset_id, vulnerability_id, age_in_days FROM
    fact_asset_vulnerability_age
    '''

    ret = {}

    debug.printd('requesting vulnerability age information')

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    vulndata = scanner.conn.adhoc_report(squery, sites, api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(vulndata))
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        assetid = int(i[0])
        vid = int(i[1])
        age = float(i[2])
        if assetid not in ret:
            ret[assetid] = {}
        if vid not in ret[assetid]:
            ret[assetid][vid] = age
        else:
            if age > ret[assetid][vid]:
                ret[assetid][vid] = age
    return ret

def vuln_extraction(scanner, vulnquery_where, writefile=None, readfile=None):
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
    dv.malware_kits, dv.vulnerability_id
    FROM fact_asset_vulnerability_instance favi 
    JOIN dim_asset da USING (asset_id) 
    JOIN dim_vulnerability dv USING (vulnerability_id) 
    JOIN dim_site_asset dsa USING (asset_id) 
    JOIN dim_site ds USING (site_id) 
    JOIN dim_vulnerability_status dvs USING (status_id) 
    JOIN dim_protocol dp USING (protocol_id) 
    JOIN dim_service dsvc USING (service_id) 
    JOIN vuln_references vr USING (vulnerability_id) 
    %s
    ORDER BY ds.name, da.ip_address
    ''' % vulnquery_where

    debug.printd('requesting vulnerability details')

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    agedata = vuln_get_age_data(scanner)

    if readfile != None:
        debug.printd('reading vulnerability data from %s' % readfile)
        fd = open(readfile, 'r')
        vulndata = fd.read()
        fd.close()
    else:
        vulndata = scanner.conn.adhoc_report(squery, sites,
            api_version='1.3.2')

    if writefile != None:
        fd = open(writefile, 'w')
        fd.write(vulndata)
        fd.close()
        sys.exit(0)

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
        v.known_exploits = False
        v.known_malware = False
        if int(i[13]) > 0:
            v.known_exploits = True
        if int(i[14]) > 0:
            v.known_malware = True
        v.vid = i[15]
        idx = i[7].find('.')
        if idx > 0:
            dstr = i[7][:idx]
        else:
            dstr = i[7]
        v.age_days = vuln_age_days(v, agedata)
        dt = datetime.datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=pytz.UTC)
        v.discovered_date = dt

        v.discovered_date_unix = int((v.discovered_date - \
            datetime.datetime(1970, 1, 1, tzinfo=pytz.utc)).total_seconds())

        v.cvss = float(i[11])
        for i in i[12].split(','):
            buf = i.strip()
            if 'CVE-' in buf:
                if v.cves == None:
                    v.cves = [buf,]
                else:
                    v.cves.append(buf)
            if 'RHSA-' in buf:
                if v.rhsa == None:
                    v.rhsa = [buf,]
                else:
                    v.rhsa.append(buf)

        linked += vuln_instance_link(v, scanner)

    debug.printd('%d vulnerabilities loaded' % nvulns)
    debug.printd('%d vulnerabilities linked' % linked)

    vuln.vuln_reset_uid_cache()
    for s in scanner.sitelist.keys():
        for a in scanner.sitelist[s]['assets']:
            if len(a['vulns']) == 0:
                continue
            vuln.vuln_proc_pipeline(a['vulns'],
                a['id'], a['address'], a['macaddress'],
                a['hostname'])
    vuln.expire_hosts()

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

def group_purge(scanner, gid):
    remlist = []
    debug.printd('purging assets from group %s' % gid)
    grpconfig = scanner.conn.asset_group_config(gid)
    root = ET.fromstring(grpconfig)
    a = root.find('AssetGroup')
    if a == None:
        raise Exception('autopurge group not found')
    if a.attrib['id'] != gid:
        raise Exception('server returned incorrect asset group')
    dlist = a.find('Devices')
    for i in dlist:
        remlist.append(i.attrib['id'])
    debug.printd('removing %d assets from group %s' % \
        (len(remlist), gid))
    for i in remlist:
        scanner.conn.device_delete(i)
        debug.printd('removed device %s' % i)

def site_update_from_files(scanner, sid, pathlist):
    tmpfile = tempfile.mkstemp()
    tmpfilefd = os.fdopen(tmpfile[0], 'w')
    for i in pathlist:
        try:
            fd = open(i, 'r')
        except IOError:
            debug.printd('cannot read %s, skipping site' % i)
            os.remove(tmpfile[1])
            return
        tmpfilefd.write(fd.read())
        fd.close()
    tmpfilefd.close()
    site_update_from_file(scanner, sid, tmpfile[1])
    os.remove(tmpfile[1])
    
def site_update_from_file(scanner, sid, path):
    debug.printd('updating site %s from %s' % (sid, path))
    sconf = scanner.conn.site_config(sid)
    root = ET.fromstring(sconf)
    sitetag = root.find('Site')
    if sitetag == None:
        raise Exception('response from server for site %s invalid' % \
            sid)
    ne = sitetag.find('Hosts')
    updates = 0
    try:
        fd = open(path, 'r')
    except IOError:
        sys.stderr.write('unable to read %s, skipping updates ' \
        'for site %s\n' % (path, sid))
        return

    # Expand address ranges to simplify the update
    for i in ne[:]:
        if i.tag != 'range':
            continue
        low = i.get('from')
        high = i.get('to')
        if high == None:
            continue
        ipl = list(netaddr.iter_iprange(low, high))
        debug.printd('expanding %s -> %s in site %s' % (low, high, sid))
        ne.remove(i)
        for j in ipl:
            newsub = ET.SubElement(ne, 'range')
            newsub.set('from', str(j))
        
    # First remove anything from the site we have a known exemption for
    for i in ne[:]:
        if i.tag != 'range':
            debug.printd('removing %s from %s, not a range tag' % \
                (i.text, sid))
            ne.remove(i)
            continue
        checkip = i.get('from')
        if exempt.ip_exempt(checkip):
            debug.printd('removing %s from site %s as it is exempted' % \
                (checkip, sid))
            ne.remove(i)
            updates += 1

    addrtable = []
    while True:
        buf = fd.readline()
        if buf == None or buf == '':
            break
        buf = buf.strip()
        found = False
        if exempt.ip_exempt(buf):
            continue
        addrtable.append(buf)
        for i in ne:
            if i.get('from') == buf:
                found = True
                break
        if found:
            continue
        debug.printd('adding %s to site %s' % (buf, sid))
        newsub = ET.SubElement(ne, 'range')
        newsub.set('from', buf)
        updates += 1
    fd.close()

    # Finally, remove any addresses in the site that don't seem to exist
    # anymore according to host discovery
    for i in ne[:]:
        a = i.get('from')
        if a not in addrtable:
            debug.printd('removing %s from site %s' % (a, sid))
            ne.remove(i)
            updates += 1

    if updates == 0:
        debug.printd('no updates needed for site %s' % sid)
        return
    debug.printd('%d updates for site %s' % (updates, sid))
    scanner.conn.site_save((ET.tostring(sitetag),))

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

    add_asset_properties(scanner)

    debug.printd('requesting asset groups')
    grpdata = scanner.conn.asset_group_listing()
    root = ET.fromstring(grpdata)
    for g in root:
        if g.tag != 'AssetGroupSummary':
            continue
        newgrp = {}
        newgrp['name'] = g.attrib['name']
        newgrp['id'] = g.attrib['id']
        scanner.grouplist[int(g.attrib['id'])] = newgrp
