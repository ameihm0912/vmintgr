#!/usr/bin/python

import sys
import getopt
import datetime
import pytz

import dateutil.parser

from libvmintgr import nexpose
from libvmintgr import debug
from libvmintgr import config
from libvmintgr import nexrep
from libvmintgr import nexadhoc

vmconfig = None
scanner = None

def usage():
    sys.stdout.write('usage: vmreport.py [-dh] [-f path] [-g group]\n' \
            '\n' \
            '\t-C\t\tEnable adhoc query cache\n' \
            '\t-d\t\tEnable debugging\n' \
            '\t-e time\t\tSpecify end of statistics window\n' \
            '\t-f path\t\tPath to configuration file\n' \
            '\t-g group\tReport on asset group ID\n' \
            '\t-h\t\tUsage\n' \
            '\t-s time\t\tSpecify start of statistics window\n')

def group_tac(gid, window_start, window_end):
    nexpose.site_extraction(scanner)
    assetset = nexrep.asset_gid_scan_set(scanner, gid, window_start,
        window_end)

def domain():
    global vmconfig
    global scanner
    confpath = None
    repgid = None
    # Default to a 31 day window.
    window_end = pytz.timezone('UTC').localize(datetime.datetime.utcnow())
    window_start = window_end - datetime.timedelta(days=31)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'Cde:hf:g:s:')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
        sys.exit(1)
    for o, a in opts:
        if o == '-h':
            usage()
            sys.exit(0)
        elif o == '-C':
            nexadhoc.nexpose_adhoc_cache(True)
        elif o == '-d':
            debug.setdebugging(True)
        elif o == '-e':
            window_end = dateutil.parser.parse(a)
            window_end = window_end.replace(tzinfo=dateutil.tz.tzutc())
        elif o == '-f':
            confpath = a
        elif o == '-g':
            repgid = a
        elif o == '-s':
            window_start = dateutil.parser.parse(a)
            window_start = window_start.replace(tzinfo=dateutil.tz.tzutc())

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
