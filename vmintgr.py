#!/usr/bin/python2

import sys
import getopt
import fcntl
import os
import shutil
import calendar
import time
import errno

sys.path.append('../pnexpose')

import libvmintgr

import pnexpose

vmconfig = None
debug = False
scanner = None
pidfd = None
vmdbconn = None

# Used for -w and -r
vulns_readfile = None
vulns_writefile = None

def usage():
    sys.stdout.write('usage: vmintgr.py [-AadDeGhmRSs] [-f path] [-r path]' \
        ' [-w path]\n' \
        '\n' \
        '\t-A\t\tAsset grouping\n' \
        '\t-a\t\tDevice authentication failures\n' \
        '\t-d\t\tDebug mode\n' \
        '\t-D\t\tDevice auto-purge\n' \
        '\t-e\t\tEscalation pass against database\n' \
        '\t-f path\t\tPath to configuration file\n' \
        '\t-G\t\tAsset group list\n' \
        '\t-h\t\tUsage\n' \
        '\t-m\t\tDequeue events to MozDef\n' \
        '\t-r path\t\tWith -V, read vulnerabilities from file\n' \
        '\t-R\t\tStored report list\n' \
        '\t-S\t\tSite list\n' \
        '\t-s\t\tSite sync\n' \
        '\t-t\t\tReport test\n' \
        '\t-V\t\tProcess vulnerabilities from source\n' \
        '\t-w path\t\tWith -V, just write vulnerabilities to file\n')

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
    
def wf_escalations():
    libvmintgr.printd('starting escalation workflow...')
    libvmintgr.escalate_vulns(vmconfig.escdir, vmconfig.escalate_vulns,
        vmconfig.escalate_compliance)
    
def wf_mozdef():
    libvmintgr.printd('dequeueing events to mozdef...')
    libvmintgr.mozdef_proc(vmconfig.escdir,
        vmconfig.mozdef_compliance_url, vmconfig.mozdef_vuln_url)

def wf_reptest():
    libvmintgr.site_extraction(scanner)
    libvmintgr.reptest(scanner)

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
        libvmintgr.site_update_from_files(scanner, i, vmconfig.devsync_map[i])

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

def wf_vuln_proc():
    libvmintgr.printd('executing vulnerability processing automation...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.vuln_extraction(scanner, vmconfig.vulnquery_where,
        writefile=vulns_writefile, readfile=vulns_readfile)

def wf_list_reports():
    reports = libvmintgr.report_list(scanner)
    for repent in reports.keys():
        sys.stdout.write('%s,\"%s\",\"%s\",\"%s\"\n' % \
            (repent, reports[repent]['name'],
            reports[repent]['last-generated'],
            reports[repent]['status']))

def dbbackup(path):
    nfiles = 5
    y = ['.' + str(x) for x in range(nfiles)]
    bfiles = [path + x for x in y]
    if not os.path.isfile(bfiles[0]):
        try:
            shutil.copyfile(path, bfiles[0])
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise
        return
    m0 = os.path.getmtime(bfiles[0])
    now = calendar.timegm(time.gmtime())
    if (now - m0) < float(vmconfig.dbbackup):
        return
    libvmintgr.debug.printd('doing database backup')
    try:
        os.remove(bfiles[-1])
    except OSError as e:
        if e.errno == errno.ENOENT:
            pass
        else:
            raise
    for i in reversed(bfiles[:-1]):
        try:
            os.rename(i, bfiles[bfiles.index(i) + 1])
        except OSError as e:
            if e.errno == errno.ENOENT:
                pass
            else:
                raise
    try:
        shutil.copyfile(path, bfiles[0])
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise

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
    global vulns_readfile
    global vulns_writefile
    confpath = None
    replistmode = False
    authfailmode = False
    agroupmode = False
    sitelistmode = False
    sitesyncmode = False
    grouplistmode = False
    purgemode = False
    escmode = False
    selection = False
    vulnproc = False
    reptest = False
    mozdefmode = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'AadDef:GhmRr:SsVtw:')
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
        elif o == '-r':
            vulns_readfile = a
        elif o == '-d':
            libvmintgr.setdebugging(True)
        elif o == '-D':
            purgemode = True
            selection = True
        elif o == '-e':
            escmode = True
            selection = True
        elif o == '-G':
            grouplistmode = True
            selection = True
        elif o == '-m':
            mozdefmode = True
            selection = True
        elif o == '-S':
            sitelistmode = True
            selection = True
        elif o == '-s':
            sitesyncmode = True
            selection = True
        elif o == '-t':
            reptest = True
            selection = True
        elif o == '-V':
            vulnproc = True
            selection = True
        elif o == '-w':
            vulns_writefile = a
        elif o == '-f':
            confpath = a

    if not selection:
        sys.stderr.write('no operation selected, see usage (-h)\n')
        sys.exit(1)

    vmconfig = libvmintgr.VMConfig(confpath)
    libvmintgr.set_compliance_urls(vmconfig.compliance_url,
        vmconfig.compliance_link)

    open_pidfile()

    dbbackup(vmconfig.sql_path)
    vmdbconn = libvmintgr.db_init(vmconfig.sql_path)
    vmdbconn.create()
    libvmintgr.load_exemptions(vmconfig.exempt_dir)
    libvmintgr.load_vulnauto(vmconfig.vulnauto_dir, vmdbconn)

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
    elif vulnproc:
        wf_vuln_proc()
    elif reptest:
        wf_reptest()
    elif escmode:
        wf_escalations()
    elif mozdefmode:
        wf_mozdef()

if __name__ == '__main__':
    domain()

sys.exit(0)
