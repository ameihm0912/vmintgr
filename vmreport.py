#!/usr/bin/python

import sys
import getopt
import datetime
import pytz

from libvmintgr import nexpose
from libvmintgr import debug
from libvmintgr import config
from libvmintgr import nexrep

vmconfig = None
scanner = None

def usage():
    sys.stdout.write('usage: vmreport.py [-dh] [-f path] [-g group]\n' \
            '\n' \
            '\t-d\t\tEnable debugging\n' \
            '\t-f path\t\tPath to configuration file\n' \
            '\t-g group\tReport on asset group ID\n' \
            '\t-h\t\tUsage\n')

def group_tac(gid, window_start, window_end):
    nexpose.site_extraction(scanner)
    assetset = nexrep.asset_gid_scan_set(scanner, gid, window_start,
        window_end)

def domain():
    global vmconfig
    global scanner
    confpath = None
    repgid = None
    # XXX For now just trend over a period of 31 days, this should be made
    # more flexible in the future (allow a start and end date to be supplied)
    window_end = pytz.timezone('UTC').localize(datetime.datetime.utcnow())
    window_start = window_end - datetime.timedelta(days=31)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'dhf:g:')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
        sys.exit(1)
    for o, a in opts:
        if o == '-h':
            usage()
            sys.exit(0)
        elif o == '-d':
            debug.setdebugging(True)
        elif o == '-f':
            confpath = a
        elif o == '-g':
            repgid = a

    if repgid == None:
        sys.stderr.write('must specify reporting group id with -g\n')
        sys.exit(1)

    vmconfig = config.VMConfig(confpath)

    nexpose.nexpose_consolelogin(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)
    scanner = nexpose.nexpose_connector(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)

    group_tac(repgid, window_start, window_end)

if __name__ == '__main__':
    domain()

sys.exit(0)
