import sys
import os
import ConfigParser

import debug

class vulnerability(object):
    def __init__(self):
        self.sitename = None
        self.assetid = None
        self.ipaddr = None
        self.hostname = None
        self.macaddr = None
        self.title = None
        self.discovered_date = None
        self.cves = None
        self.cvss = None
        self.rhsa = None

    def __str__(self):
        buf = '----- %d %s | %s\n' \
            'sitename: %s\n' \
            'hostname: %s\n' \
            'macaddr: %s\n' \
            'discovered: %s\n' \
            '----' % (self.assetid, self.ipaddr, self.title,
                self.sitename, self.hostname, self.macaddr,
                self.discovered_date)
        return buf

def load_vulnauto(dirpath):
    debug.printd('reading vulnerability automation data...')
    dirlist = os.listdir(dirpath)
    for i in dirlist:
        load_vulnauto_list(os.path.join(dirpath, i))

def load_vulnauto_list(path):
    debug.printd('reading automation data from %s' % path)
    cp = ConfigParser.SafeConfigParser()
    cp.read(path)

    for s in cp.sections():
        pass
