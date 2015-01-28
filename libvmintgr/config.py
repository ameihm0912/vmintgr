# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

import sys

class VMConfig(object):
    _def_conf_path = './vmintgr.conf'

    def __init__(self, fn):
        self.vms_username = None
        self.vms_password = None
        self.vms_type = None
        self.vms_server = None
        self.vms_port = 0
        self.pidfile = None
        self.sql_path = None
        self.logfile = None
        self.mozdef_compliance_url = None
        self.mozdef_vuln_url = None
        self.compliance_url = None
        self.compliance_link = None
        self.dbbackup = 28800

        self.vulnquery_where = ''

        self.exempt_dir = None

        self.vulnauto_dir = None
        self.escdir = None
        self.escalate_vulns = False
        self.escalate_compliance = False

        self.purge_groupid = None

        self.devsync_map = {}

        self.devauth_report = None

        if fn == None:
            fn = self._def_conf_path

        self._cp = ConfigParser.SafeConfigParser()
        self._cp.read(fn)
        if len(self._cp.sections()) == 0:
            sys.stderr.write('error reading %s\n' % fn)
            sys.exit(1)

        for s in self._cp.sections():
            if s == 'vms':
                mdesc = 'vms'
            elif s == 'device_authfail':
                mdesc = 'device_authfail'
            elif s == 'device_sync':
                mdesc = 'device_sync'
            elif s == 'exemptions':
                mdesc = 'exemptions'
            elif s == 'vulnauto':
                mdesc = 'vulnauto'
            elif s == 'autopurge':
                mdesc = 'autopurge'
            elif s == 'debug':
                mdesc = 'debug'
            else:
                sys.stderr.write('invalid configuration section %s\n' % \
                    s)
                sys.exit(1)
            parsefunc = getattr(self, 'parse_' + s)
            for k, v in self._cp.items(s):
                parsefunc(k, v, s)

    def parse_vulnauto(self, k, v, s):
        if k == 'vulndir':
            self.vulnauto_dir = v
        elif k == 'escalations':
            self.escdir = v
        elif k == 'escalate_vulns':
            if v == '1':
                self.escalate_vulns = True
            else:
                self.escalate_vulns = False
        elif k == 'escalate_compliance':
            if v == '1':
                self.escalate_compliance = True
            else:
                self.escalate_compliance = False
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)

    def parse_debug(self, k, v, s):
        if k == 'vulnquery_where':
            self.vulnquery_where = v
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)

    def parse_autopurge(self, k, v, s):
        if k == 'groupid':
            self.purge_groupid = v
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)

    def parse_exemptions(self, k, v, s):
        if k == 'listdir':
            self.exempt_dir = v
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)

    def parse_device_sync(self, k, v, s):
        self.devsync_map[k] = v.split()

    def parse_device_authfail(self, k, v, s):
        if k == 'repid':
            self.devauth_report = v
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)

    def parse_vms(self, k, v, s):
        if k == 'username':
            self.vms_username = v
        elif k == 'password':
            self.vms_password = v
        elif k == 'type':
            self.vms_type = v
        elif k == 'server':
            self.vms_server = v
        elif k == 'port':
            self.vms_port = int(v)
        elif k == 'pidfile':
            self.pidfile = v
        elif k == 'sqldb':
            self.sql_path = v
        elif k == 'mozdef_compliance':
            self.mozdef_compliance_url = v
        elif k == 'mozdef_vuln':
            self.mozdef_vuln_url = v
        elif k == 'dbbackup':
            self.dbbackup = v
        elif k == 'logfile':
            self.logfile = v
        elif k == 'compliance_url':
            self.compliance_url = v
        elif k == 'compliance_link':
            self.compliance_link = v
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)
