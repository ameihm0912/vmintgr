# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
import xml.etree.ElementTree as ET
try:
    import StringIO
except ImportError:
    import io
    StringIO = io.StringIO
import csv
import time
import datetime
import pytz
import tempfile
import urllib
try:
    from urllib2 import build_opener, install_opener, Request, urlopen, HTTPCookieProcessor
except ImportError:
    import urllib.request
    from urllib.request import build_opener, install_opener, Request, urlopen, HTTPCookieProcessor
try:
    from cookielib import LWPCookieJar
except ImportError:
    from http.cookiejar import LWPCookieJar
import re
import netaddr

import libvmintgr.debug as debug
import libvmintgr.vuln as vuln
import libvmintgr.exempt as exempt
import libvmintgr.nexadhoc as nexadhoc

sys.path.append('../../pnexpose')
import pnexpose

cookiejar = None
nx_console_server = None
nx_console_port = None

CREDSTATUS_NOCREDSUP = 1
CREDSTATUS_LOGINFAIL = 2
CREDSTATUS_LOGINSUCC = 3
CREDSTATUS_LOGINPRIV = 4
CREDSTATUS_LOGINROOT = 5
CREDSTATUS_LOGINADMN = 6

class nexpose_connector(object):
    def __init__(self, server, port, user, pw):
        self.conn = pnexpose.Connection(server, port, user, pw)
        self.sitelist = {}
        self.grouplist = {}

def nexpose_consolelogin(server, port, user, pw):
    global nx_console_server
    global nx_console_port
    global cookiejar

    loginurl = 'https://%s:%d/data/user/login' % (server, port)
    vals = { 'nexposeccusername': user,
             'nexposeccpassword': pw,
             'loginRedir': '/home.jsp',
             'screenresolution': '1280x800' }

    nx_console_server = server
    nx_console_port = port

    cookiejar = LWPCookieJar()
    opener = build_opener(HTTPCookieProcessor(cookiejar))
    install_opener(opener)
    formdata = urllib.urlencode(vals)
    req = Request(loginurl, formdata)
    resp = urlopen(req)

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

    if len(reploc) > 1 and reploc.startswith('/'):
        reploc = reploc[1:]
    url = 'https://%s:%d/%s' % (nx_console_server, nx_console_port, reploc)

    opener = build_opener(HTTPCookieProcessor(cookiejar))
    install_opener(opener)
    req = Request(url, None)
    resp =urlopen(req)
    return resp.read()

def software_extraction(scanner, targetpkg):
    squery = '''
    SELECT da.asset_id, da.ip_address, da.host_name,
    ds.name, ds.version
    FROM dim_asset da
    JOIN dim_asset_software USING (asset_id)
    JOIN dim_software ds USING (software_id)
    WHERE ds.name ILIKE '%s'
    ''' % targetpkg

    buf = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(buf))
    ret = {}
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        asset_id = i[0]
        ip = i[1]
        hname = i[2]
        swname = i[3]
        swver = i[4]

        if asset_id not in ret:
            ret[asset_id] = []
        new = {}
        new['ipaddr'] = ip
        new['hostname'] = hname
        new['swname'] = swname
        new['swver'] = swver
        ret[asset_id].append(new)
    return ret

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

    ret = nexadhoc.nexpose_adhoc(scanner, squery, sites, api_version='1.3.2')
    print ret
    sys.exit(0)

def build_targethost_where(scanner, targethosts):
    buf = ''
    for i in targethosts:
        if buf != '':
            buf = buf + ' OR '
        buf = buf + '(ip_address = \'%s\') OR (host_name = \'%s\')' % \
            (i, i)

    squery = '''
    SELECT asset_id FROM dim_asset
    WHERE %s''' % buf

    ret = nexadhoc.nexpose_adhoc(scanner, squery, [], api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(ret))
    retbuf = 'WHERE '
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        if retbuf != 'WHERE ':
            retbuf = retbuf + ' OR '
        retbuf = retbuf + '(asset_id = %s)' % i[0]

    return retbuf

def add_asset_properties(scanner):
    squery = '''
    SELECT asset_id, ds.name AS site_name, da.ip_address, da.host_name,
    da.mac_address, dos.description AS operating_system, dht.description,
    dos.asset_type, dos.cpe, fa.aggregated_credential_status_id FROM dim_asset da
    JOIN dim_operating_system dos USING (operating_system_id) 
    JOIN dim_host_type dht USING (host_type_id) 
    JOIN dim_site_asset dsa USING (asset_id) 
    JOIN dim_site ds USING (site_id)
    JOIN fact_asset fa USING (asset_id)
    '''

    debug.printd('requesting additional asset properties')

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    vulndata = nexadhoc.nexpose_adhoc(scanner, squery, sites,
        api_version='2.0.2')

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
                a['credsok'] = False
                continue
            a['hostname'] = atable[a['id']][2]
            a['macaddress'] = atable[a['id']][3]
            a['os'] = atable[a['id']][4]
            a['credsok'] = False
            cstatus = atable[a['id']][8]
            if int(cstatus) >= CREDSTATUS_LOGINSUCC:
                a['credsok'] = True

def vuln_extraction(scanner, vulnquery_where, writefile=None, readfile=None,
    targetcve=None, targethosts=False):
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
    dv.malware_kits, dv.vulnerability_id,
    dv.description, dv.cvss_vector,
    proofAsText(favi.proof), age_in_days
    FROM fact_asset_vulnerability_instance favi 
    JOIN dim_asset da USING (asset_id) 
    JOIN dim_vulnerability dv USING (vulnerability_id) 
    JOIN dim_site_asset dsa USING (asset_id) 
    JOIN dim_site ds USING (site_id) 
    JOIN dim_vulnerability_status dvs USING (status_id) 
    JOIN dim_protocol dp USING (protocol_id) 
    JOIN dim_service dsvc USING (service_id) 
    JOIN vuln_references vr USING (vulnerability_id) 
    JOIN fact_asset_vulnerability_age USING (asset_id, vulnerability_id)
    %s
    ORDER BY ds.name, da.ip_address
    ''' % vulnquery_where

    debug.printd('requesting vulnerability details')

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    if readfile != None:
        debug.printd('reading vulnerability data from %s' % readfile)
        fd = open(readfile, 'r')
        vulndata = fd.read()
        fd.close()
    else:
        vulndata = nexadhoc.nexpose_adhoc(scanner, squery, sites,
            api_version='2.0.2')

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
        v.description = i[16]
        v.cvss_vector = i[17]
        v.proof = i[18]
        v.age_days = i[19]
        idx = i[7].find('.')
        if idx > 0:
            dstr = i[7][:idx]
        else:
            dstr = i[7]
        dt = datetime.datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
        dt = dt.replace(tzinfo=pytz.UTC)
        v.discovered_date = dt

        def get_total_seconds(td):
            return (td.microseconds + (td.seconds + td.days * 24 * 3600) \
                    * 1e6) / 1e6
        v.discovered_date_unix = int(get_total_seconds(v.discovered_date - \
            datetime.datetime(1970, 1, 1, tzinfo=pytz.utc)))

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
            # If in target CVE report mode, just report on the CVE but
            # don't actually process the vulnerability
            if targetcve != None:
                vuln.vuln_cvereport(a, targetcve)
                continue
            elif targethosts:
                vuln.vuln_hostreport(a)
                continue
            vuln.vuln_proc_pipeline(a['vulns'],
                a['id'], a['address'], a['macaddress'],
                a['hostname'])

    if targetcve != None or targethosts:
        return

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
    sitedata = scanner.conn.list_sites()

    for s in sitedata:
        siteinfo = {}
        siteinfo['name'] = s.name
        siteinfo['id'] = str(s.id)
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

def asset_update_group(scanner, groupdata):
    usegroup = -1
    vgent = groupdata['autoentry']

    for g in scanner.grouplist:
        if scanner.grouplist[g]['name'] == vgent.title:
            usegroup = int(scanner.grouplist[g]['id'])
    if usegroup == -1:
        debug.printd('creating new asset group')
    else:
        debug.printd('updating asset group %d' % usegroup)

    e = ET.Element('AssetGroup', attrib={'id': str(usegroup),
        'name': vgent.title, 'description': vgent.description})
    de = ET.SubElement(e, 'Devices')
    for i in groupdata['assetids']:
        newsub = ET.SubElement(de, 'device', attrib={'id': str(i)})
    scanner.conn.asset_group_save((ET.tostring(e),))

def adhoc_group(scanner, tgfile):
    groupdata = {}

    addrlist = []
    fd = open(tgfile, 'r')
    while True:
        buf = fd.readline()
        if buf == None or buf == '':
            break
        addrlist.append(buf.strip())
    fd.close()
    debug.printd('will group on %d addresses' % len(addrlist))

    # Create a psuedo vulnauto entry to support creation of the adhoc
    # group.
    groupdata['autoentry'] = vuln.VulnAutoEntry('adhoc')
    groupdata['autoentry'].description = 'adhoc'
    groupdata['autoentry'].title = 'adhoc'

    # Find each asset that matches an entry in the addrlist; since this is
    # primarily used with MIG database dumps we just match on IP address.
    # This could be expanded to match on hostname and other fields if needed.
    groupdata['assetids'] = []
    for s in scanner.sitelist:
        for a in scanner.sitelist[s]['assets']:
            if a['address'] in addrlist:
                groupdata['assetids'].append(a['id'])
    debug.printd('matched on %d assets' % len(groupdata['assetids']))

    # Create the adhoc group.
    debug.printd('updating adhoc group')
    asset_update_group(scanner, groupdata)

def asset_grouping(scanner):
    # Each automation entry that was loaded will result in an asset group
    groupdata = {}
    for x in vuln.vulnautolist:
        if x.name not in groupdata:
            groupdata[x.name] = {}
            groupdata[x.name]['autoentry'] = x
            groupdata[x.name]['assetids'] = []
    # Also add the default
    groupdata['default'] = {}
    groupdata['default']['autoentry'] = vuln.defaultvulnauto
    groupdata['default']['assetids'] = []
    for s in scanner.sitelist:
        for a in scanner.sitelist[s]['assets']:
            vent = vuln.vuln_auto_finder(a['address'], a['macaddress'],
                a['hostname'])
            if vent == None:
                continue
            for i in groupdata:
                if groupdata[i]['autoentry'].name == vent.name:
                    groupdata[i]['assetids'].append(a['id'])

    for x in groupdata:
        asset_update_group(scanner, groupdata[x])

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
