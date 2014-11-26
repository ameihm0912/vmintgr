import sys
import xml.etree.ElementTree as ET

sys.path.append('../../pnexpose')

import pnexpose
import debug

class nexpose_connector(object):
    def __init__(self, server, port, user, pw):
        self.conn = pnexpose.nexposeClient(server, port, user, pw)
        self.sitelist = {}

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
                newdev['id'] = d.attrib['id']
                newdev['address'] = d.attrib['address']
                scanner.sitelist[sid]['assets'].append(newdev)
