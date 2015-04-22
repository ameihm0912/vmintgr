# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import ConfigParser
import xml.etree.ElementTree as ET
import sys
import os
import netaddr
import json
import StringIO
import csv

import debug
import misc
import nexadhoc

spoolconf = None

class SpoolData(object):
    def __init__(self):
        self.new_requests = []
        self.exec_requests = []

class SpoolConfig(object):
    def __init__(self, path):
        self.spooldir = None
        self.siteid = None

        cp = ConfigParser.SafeConfigParser()
        cp.read(path)
        for k, v in cp.items('spooler'):
            if k == 'spooldir':
                self.spooldir = v
            elif k == 'siteid':
                self.siteid = v

def spool_update_site_config(scanner, alist):
    if len(alist) == 0:
        return

    foundlist = {}
    for x in alist:
        foundlist[x] = False

    debug.printd('updating site configuration for site %s' % spoolconf.siteid)
    siteconf = scanner.conn.site_config(spoolconf.siteid)
    root = ET.fromstring(siteconf)
    siteentry = root.find('Site')
    if siteentry == None:
        raise Exception('no Site subelement in response')
    hostlist = siteentry.find('Hosts')
    if hostlist == None:
        raise Exception('no Hosts subelement in response')

    for s in hostlist:
        if s.tag != 'range':
            continue
        low = s.get('from')
        high = s.get('to')
        plist = []
        if high != None:
            ipl = list(netaddr.iter_iprange(low, high))
            plist = [str(x) for x in ipl]
        else:
            plist = [low,]
        for a in plist:
            if a in foundlist:
                foundlist[a] = True

    for i in foundlist:
        if foundlist[i]:
            debug.printd('site already has %s' % i)
            continue
        debug.printd('adding %s' % i)
        newsub = ET.SubElement(hostlist, 'range')
        newsub.set('from', i)
    scanner.conn.site_save((ET.tostring(siteentry),))

def spool_status(scanner, requests):
    for x in requests:
        spool_status_request(scanner, x)

def spool_status_request(scanner, request):
    debug.printd('checking status of scan %s' % request['scanid'])
    resp = scanner.conn.scan_status(request['scanid'])

    response = ET.fromstring(resp)
    if response.tag != 'ScanStatusResponse' or \
        response.get('success') != '1':
            raise Exception('scan status request failed')
    if response.get('status') != 'finished':
        debug.printd('scan %s not complete' % request['scanid'])
        return
    debug.printd('scan %s is complete' % request['scanid'])

    # Request the results
    scanresults = spool_scan_results(scanner, request['scanid'], \
        request['target'])
    request = spool_extension_sw(request, '.exec', '.done')
    request['findings'] = scanresults
    fd = open(request['path'], 'w')
    json.dump(request, fd)
    fd.close()

def spool_scan_results(scanner, scanid, target):
    retvuln = []

    squery = '''
    SELECT da.asset_id, da.ip_address,
    da.host_name, da.mac_address,
    dv.title AS vulnerability,
    round(dv.cvss_score::numeric, 2) AS cvss_score
    FROM fact_asset_scan_vulnerability_finding favf
    JOIN dim_asset da USING (asset_id)
    JOIN dim_vulnerability dv USING (vulnerability_id)
    WHERE favf.scan_id = %s AND
    da.ip_address = '%s'
    ''' % (scanid, target)

    debug.printd('requesting vulnerability results...')
    buf = nexadhoc.nexpose_adhoc(scanner, squery, [spoolconf.siteid,], \
        scan_ids=[scanid,], api_version='1.3.2')
    reader = csv.reader(StringIO.StringIO(buf))
    for i in reader:
        if len(i) == 0:
            continue
        if i[0] == 'asset_id':
            continue
        v = {}
        v['assetid'] = int(i[0])
        v['ipaddress'] = i[1]
        v['hostname'] = i[2]
        v['macaddress'] = i[3]
        v['title'] = i[4]
        v['cvss'] = float(i[5])
        retvuln.append(v)

    return retvuln

def spool_scan(scanner, requests):
    for x in requests:
        spool_scan_request(scanner, x)

def spool_scan_request(scanner, request):
    spool_extension_sw(request, '.new', '.exec')
    debug.printd('requesting scan for %s' % request['target'])
    scanid = spool_scan_address(scanner, request['target'])
    debug.printd('running as scanid %s' % scanid)
    request['scanid'] = scanid
    fd = open(request['path'], 'w')
    json.dump(request, fd)
    fd.close()

def spool_scan_address(scanner, address):
    root = ET.Element('Hosts')
    newsub = ET.SubElement(root, 'range')
    newsub.set('from', address)
    resp = scanner.conn.site_device_scan(spoolconf.siteid, \
        (ET.tostring(root),))
    response = ET.fromstring(resp)
    if response.tag != 'SiteDevicesScanResponse' or \
        response.get('success') != '1':
        raise Exception('spool_scan_address failed')
    scandata = response.find('Scan')
    return scandata.attrib['scan-id']

def process_spoolfile(path):
    fd = open(path, 'r')
    buf = json.load(fd, object_hook=misc.decode_dict)
    buf['path'] = path
    fd.close()
    return buf

def spool_extension_sw(request, old, new):
    path = request['path']
    ri = path.rfind('.')
    if ri == '-1':
        raise Exception('extension character not found')
    if path[ri:] != old:
        raise Exception('unexpected extension')
    request['path'] = path[:ri] + new
    os.rename(path, request['path'])
    return request

def load_spool(spooldir):
    ret = SpoolData()
    spoolfiles = os.listdir(spooldir)
    for x in [os.path.join(spooldir, y) for y in spoolfiles]:
        if x.endswith('new'):
            ret.new_requests.append(process_spoolfile(x))
        elif x.endswith('exec'):
            ret.exec_requests.append(process_spoolfile(x))
    for x in ret.new_requests:
        spool_valid_new_request(x)
    for x in ret.exec_requests:
        spool_valid_exec_request(x)
    return ret

def spool_valid_new_request(req):
    for k in ['type', 'target']:
        if k not in req:
            raise Exception('key %s not found in new request' % k)

def spool_valid_exec_request(req):
    for k in ['type', 'target', 'scanid', 'path']:
        if k not in req:
            raise Exception('key %s not found in exec request' % k)

#
# The spool runner executes spooled scan requests, using a spool configuration
# that indicates the site the scans should occur in, and the directory
# request and response information should be included in.
#
def spool_runner(path, scanner):
    global spoolconf

    sitedata = []
    spoolconf = SpoolConfig(path)
    spooldata = load_spool(spoolconf.spooldir)

    # For any new targets, make sure the site configuration has this target
    # in scope.
    targetlist = [x['target'] for x in spooldata.new_requests]
    debug.printd('%d new requests' % len(spooldata.new_requests))
    spool_update_site_config(scanner, targetlist)

    # For any new targets, initiate the scans
    spool_scan(scanner, spooldata.new_requests)

    # For any existing targets, check the status, collecting results
    # if available.
    debug.printd('%d in-flight requests' % len(spooldata.exec_requests))
    spool_status(scanner, spooldata.exec_requests)
