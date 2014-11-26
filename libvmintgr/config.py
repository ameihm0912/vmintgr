import ConfigParser
import sys

class VMConfig(object):
    _def_conf_path = './vmintgr.conf'

    def __init__(self, fn):
        self.vms_username = None
        self.vms_password = None
        self.vms_type = None
        self.vms_server = None
        self.vms_port = 0

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
            else:
                sys.stderr.write('invalid configuration section %s\n' % \
                    s)
                sys.exit(1)
            parsefunc = getattr(self, 'parse_' + s)
            for k, v in self._cp.items(s):
                parsefunc(k, v, s)

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
        else:
            sys.stderr.write('option %s not available under %s\n' % \
                (k, s))
            sys.exit(1)
