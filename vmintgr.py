#!/usr/bin/python2

import sys
import getopt

sys.path.append('../pnexpose')

import libvmintgr

import pnexpose

vmconfig = None
debug = False
scanner = None

def usage():
    sys.stdout.write('usage: vmintgr.py [-h] [-f path]\n')

def wf_asset_grouping():
    libvmintgr.printd('starting asset grouping workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.vuln_extraction(scanner)

def domain():
    global vmconfig
    global debug
    global scanner
    confpath = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'df:h')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
        sys.exit(1)
    for o, a in opts:
        if o == '-h':
            usage()
            sys.exit(0)
        elif o == '-d':
            libvmintgr.setdebugging(True)
        elif o == '-f':
            confpath = a

    vmconfig = libvmintgr.VMConfig(confpath)
    scanner = libvmintgr.nexpose_connector(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)

    wf_asset_grouping()

if __name__ == '__main__':
    domain()

sys.exit(0)
