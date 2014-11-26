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
        self.cve = None
        self.cvss = None
        self.rhsa = None

    def __str__(self):
        buf = '%d %s | %s' % (self.assetid, self.ipaddr, self.title)
        return buf
