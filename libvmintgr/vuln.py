import sys

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
