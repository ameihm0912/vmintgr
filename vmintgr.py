#!/usr/bin/python2

import sys
import getopt
import fcntl
import os

sys.path.append('../pnexpose')

import libvmintgr

import pnexpose

vmconfig = None
debug = False
scanner = None
pidfd = None
vmdbconn = None

def usage():
    sys.stdout.write('usage: vmintgr.py [-AadDGhRSs] [-f path]\n' \
        '\n' \
        '\t-A\t\tAsset grouping\n' \
        '\t-a\t\tDevice authentication failures\n' \
        '\t-d\t\tDebug mode\n' \
        '\t-D\t\tDevice auto-purge\n' \
        '\t-f path\t\tPath to configuration file\n' \
        '\t-G\t\tAsset group list\n' \
        '\t-h\t\tUsage\n' \
        '\t-R\t\tStored report list\n' \
        '\t-S\t\tSite list\n' \
        '\t-s\t\tSite sync\n')

def wf_asset_grouping():
    libvmintgr.printd('starting asset grouping workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)

def wf_group_list():
    libvmintgr.printd('starting asset group list workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    for i in scanner.grouplist.keys():
        grpent = scanner.grouplist[i]
        sys.stdout.write('%s %s\n' % \
            (str(i).ljust(6), grpent['name']))

def wf_auto_purge():
    libvmintgr.printd('starting asset purge workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.group_purge(scanner, vmconfig.purge_groupid)
    
def wf_site_list():
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    for i in scanner.sitelist.keys():
        s = scanner.sitelist[i]
        sys.stdout.write('%s %s %d\n' % \
            (s['id'].ljust(6), s['name'].ljust(30), len(s['assets'])))

def wf_site_sync():
    libvmintgr.printd('executing site device sync workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    for i in vmconfig.devsync_map.keys():
        libvmintgr.site_update_from_file(scanner, i, vmconfig.devsync_map[i])

def wf_device_auth_fail():
    libvmintgr.printd('executing device authentication failure workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    ret = libvmintgr.generate_report(scanner, vmconfig.devauth_report)
    faildata = libvmintgr.nexpose_parse_custom_authfail(scanner, ret)
    # XXX Add exemption handling here, probably based on a wildcard host
    # match or CIDR match
    for ln in faildata:
        sys.stdout.write('%s %s %s %s\n' % \
            (ln['ip'].ljust(17), ln['hostname'].ljust(60),
            ln['credstatus'].ljust(10), ln['sites']))

def wf_list_reports():
    reports = libvmintgr.report_list(scanner)
    for repent in reports.keys():
        sys.stdout.write('%s,\"%s\",\"%s\",\"%s\"\n' % \
            (repent, reports[repent]['name'],
            reports[repent]['last-generated'],
            reports[repent]['status']))

def open_pidfile():
    global pidfd
    pidfd = open(vmconfig.pidfile, 'w')
    fcntl.lockf(pidfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    pidfd.write(str(os.getpid()))

def domain():
    global vmconfig
    global debug
    global scanner
    global vmdbconn
    confpath = None
    replistmode = False
    authfailmode = False
    agroupmode = False
    sitelistmode = False
    sitesyncmode = False
    grouplistmode = False
    purgemode = False
    selection = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'AadDf:GhRSs')
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
            selection = True
        elif o == '-A':
            agroupmode = True
            selection = True
        elif o == '-R':
            replistmode = True
            selection = True
        elif o == '-d':
            libvmintgr.setdebugging(True)
        elif o == '-D':
            purgemode = True
            selection = True
        elif o == '-G':
            grouplistmode = True
            selection = True
        elif o == '-S':
            sitelistmode = True
            selection = True
        elif o == '-s':
            sitesyncmode = True
            selection = True
        elif o == '-f':
            confpath = a

    if not selection:
        sys.stderr.write('no operation selected, see usage (-h)\n')
        sys.exit(1)

    vmconfig = libvmintgr.VMConfig(confpath)

    open_pidfile()

    vmdbconn = libvmintgr.db_init(vmconfig.sql_path)
    vmdbconn.create()
    libvmintgr.load_exemptions(vmconfig.exempt_dir)

    libvmintgr.nexpose_consolelogin(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)
    scanner = libvmintgr.nexpose_connector(vmconfig.vms_server, \
        vmconfig.vms_port, vmconfig.vms_username, vmconfig.vms_password)

    if replistmode:
        wf_list_reports()
    elif authfailmode:
        if vmconfig.devauth_report == None:
            sys.stderr.write('must set option device_authfail/repid to use -a\n')
            sys.exit(1)
        wf_device_auth_fail()
    elif purgemode:
        wf_auto_purge()
    elif agroupmode:
        wf_asset_grouping()
    elif grouplistmode:
        wf_group_list()
    elif sitelistmode:
        wf_site_list()
    elif sitesyncmode:
        wf_site_sync()

if __name__ == '__main__':
    domain()

sys.exit(0)
