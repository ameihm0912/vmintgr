import sys
import os
import ConfigParser

import debug

vulnautolist = []

class VulnAutoEntry(object):
    def __init__(self, name):
        self.name = None
        self.mincvss = None

    def add_match(self, val):
        pass

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
        n = VulnAutoEntry(s)
        for k, v in cp.items(s):
            if k == 'mincvss':
                n.mincvss = float(v)
                pass
            elif k == 'match':
                n.add_match(v)
            elif k == 'tracker':
                # Unused right now
                pass
            else:
                sys.stderr.write('vulnauto option %s not available under ' \
                    '%s\n' % (k, s))
                sys.exit(1)
        vulnautolist.append(n)
            
