import sys
import os
import ConfigParser
from netaddr import IPNetwork, IPAddress

import debug

exemptlist_hosts = []
exemptlist_nets = []

def ip_exempt(ip):
    if ip == '':
        return False
    if ip in exemptlist_hosts:
        return True
    for i in exemptlist_nets:
        if IPAddress(ip) in IPNetwork(i):
            return True
    return False

def load_exemptions(dirpath):
    debug.printd('reading exemptions...')
    dirlist = os.listdir(dirpath)
    for i in dirlist:
        load_exemption_list(os.path.join(dirpath, i))

def load_exemption_list(path):
    debug.printd('reading exemptions from %s' % path)
    cp = ConfigParser.SafeConfigParser()
    cp.read(path)

    for s in cp.sections():
        # XXX Need to validate format and warn on syntax issues
        if '/' in s:
            exemptlist_nets.append(s)
        else:
            exemptlist_hosts.append(s)
