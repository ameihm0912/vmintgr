# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import ConfigParser
import xml.etree.ElementTree as ET
import sys
import netaddr

spoolconf = None

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
    foundlist = {}
    for x in alist:
        foundlist[x] = False
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
            continue
        newsub = ET.SubElement(hostlist, 'range')
        newsub.set('from', i)
    scanner.conn.site_save((ET.tostring(siteentry),))

def spool_scan_address(scanner, address):
    root = ET.Element('Hosts')
    newsub = ET.SubElement(root, 'range')
    newsub.set('from', address)
    resp = scanner.conn.site_device_scan(spoolconf.siteid, \
        (ET.tostring(root),))
    print resp
    response = ET.fromstring(resp)
    if response.tag != 'SiteDevicesScanResponse' or \
        response.get('success') != '1':
        raise Exception('spool_scan_address failed')
    scandata = response.find('Scan')
    return scandata.attrib['scan-id']

def spool_runner(path, scanner):
    global spoolconf

    sitedata = []
    spoolconf = SpoolConfig(path)

    testlist = []

    # Update the configuration of the spool site to make sure it includes
    # the addresses in scope
    spool_update_site_config(scanner, testlist)
