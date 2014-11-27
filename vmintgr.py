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
    sys.stdout.write('usage: vmintgr.py [-Radh] [-f path]\n')

def wf_asset_grouping():
    libvmintgr.printd('starting asset grouping workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)

def wf_device_auth_fail():
    libvmintgr.printd('executing device authentication failure workflow...')
    ret = libvmintgr.generate_report(scanner, vmconfig.devauth_report)
    faildata = libvmintgr.nexpose_parse_custom_authfail(ret)
    for ln in faildata:
        sys.stdout.write('%s %s %s\n' % \
            (ln['ip'].ljust(17), ln['hostname'].ljust(60), ln['credstatus']))

def wf_list_reports():
    reports = libvmintgr.report_list(scanner)
    for repent in reports.keys():
        sys.stdout.write('%s,\"%s\",\"%s\",\"%s\"\n' % \
            (repent, reports[repent]['name'],
            reports[repent]['last-generated'],
            reports[repent]['status']))

def domain():
    global vmconfig
    global debug
    global scanner
    confpath = None
    replistmode = False
    authfailmode = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'adf:hR')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
        sys.exit(1)
    for o, a in opts:
        if o == '-h':
            usage()
            sys.exit(0)
        elif o == '-a':
            authfailmode = True
        elif o == '-R':
            replistmode = True
        elif o == '-d':
            libvmintgr.setdebugging(True)
        elif o == '-f':
            confpath = a

    vmconfig = libvmintgr.VMConfig(confpath)
    libvmintgr.nexpose_consolelogin(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)
    scanner = libvmintgr.nexpose_connector(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)

    if replistmode:
        wf_list_reports()
    elif authfailmode:
        wf_device_auth_fail()

if __name__ == '__main__':
    domain()

sys.exit(0)
