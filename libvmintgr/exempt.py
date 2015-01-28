# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
import ConfigParser
import re
from netaddr import IPNetwork, IPAddress

import debug

exemptlist_hosts = []
exemptlist_nets = []

def ip_exempt(ip):
    if ip == '':
        return False
    # Only look at IP addresses here
    if not re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
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
