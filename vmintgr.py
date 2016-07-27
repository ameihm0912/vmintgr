#!/usr/bin/python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import getopt
import fcntl
import os
import shutil
import calendar
import time
import errno
import traceback

sys.path.append('../pnexpose')

import libvmintgr

import pnexpose

logfd = None
vmconfig = None
debug = False
scanner = None
pidfd = None
vmdbconn = None

# Used for -w and -r
vulns_readfile = None
vulns_writefile = None

def usage():
    sys.stdout.write('usage: vmintgr.py [-AadDeGhmRSs] [-c regex] [-f path] ' \
        '[-g path] [-q sqllike] [-r path] [-w path]\n' \
        '\n' \
        '\t-A\t\tAsset grouping\n' \
        '\t-a\t\tDevice authentication failures\n' \
        '\t-b\t\tAsset dump to stdout\n' \
        '\t-c regex\tReport hosts vulnerable to CVE\n' \
        '\t-d\t\tDebug mode\n' \
        '\t-D\t\tDevice auto-purge\n' \
        '\t-e\t\tEscalation pass against database\n' \
        '\t-f path\t\tPath to configuration file\n' \
        '\t-g path\t\tAdhoc group creation\n' \
        '\t-G\t\tAsset group list\n' \
        '\t-h\t\tUsage\n' \
        '\t-m\t\tDequeue events to MozDef\n' \
        '\t-q sqllike\tQuery hosts for installed software (e.g., \'%apache%\')\n' \
        '\t-r path\t\tWith -V, read vulnerabilities from file\n' \
        '\t-R\t\tStored report list\n' \
        '\t-S\t\tSite list\n' \
        '\t-s\t\tSite sync\n' \
        '\t-t\t\tReport test\n' \
        '\t-V\t\tProcess vulnerabilities from source\n' \
        '\t-w path\t\tWith -V, just write vulnerabilities to file\n' \
        '\t-x path\t\tExport issue list for hosts present in file\n' \
        '\t-z conf\t\tProcess spool data\n')

def logfile_write(s):
    logfd.write('[%s] %s\n' % (time.asctime(time.localtime()), s))

def logfile_init(path):
    global logfd
    logfd = open(path, 'a')
    libvmintgr.debug.register_hook(logfile_write)

def wf_asset_grouping():
    libvmintgr.printd('starting asset grouping workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.asset_grouping(scanner)

def wf_adhocgroup(targetgroup):
    libvmintgr.printd('starting adhoc group creation mode...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.adhoc_group(scanner, targetgroup)

def wf_asset_dump():
    libvmintgr.printd('starting asset dump workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    for s in scanner.sitelist:
        sys.stdout.write('# %s\n' % scanner.sitelist[s]['name'])
        for a in scanner.sitelist[s]['assets']:
            sys.stdout.write('%s ' % a['address'])
            hname = a['hostname']
            if hname == None or hname == '':
                sys.stdout.write('unknown\n')
            else:
                sys.stdout.write('%s\n' % hname)

def wf_swquerymode(targetpkg):
    libvmintgr.printd('starting software query workflow...')
    asw = libvmintgr.software_extraction(scanner, targetpkg)
    for i in asw:
        for ent in asw[i]:
            sys.stdout.write('%s %s %s %s\n' % \
                (ent['ipaddr'].ljust(15), ent['hostname'].ljust(50),
                ent['swname'].ljust(20), ent['swver']))

def wf_cvemode(targetcve):
    libvmintgr.printd('starting cve report workflow...')
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.vuln_extraction(scanner, vmconfig.vulnquery_where,
        writefile=vulns_writefile, readfile=vulns_readfile,
        targetcve=targetcve)

def wf_hostquery(targethosts):
    libvmintgr.printd('starting host query workflow...')
    thostbuf = []
    fd = open(targethosts, 'r')
    thostbuf = [x.strip() for x in fd.readlines()]
    fd.close()
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    wherebuf = libvmintgr.build_targethost_where(scanner, thostbuf)
    libvmintgr.vuln_extraction(scanner, wherebuf,
        writefile=vulns_writefile, readfile=vulns_readfile,
        targethosts=True)

def wf_spool(path):
    libvmintgr.printd('starting spool workflow for %s...' % path)
    libvmintgr.spool_runner(path, scanner)

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
    libvmintgr.site_extraction(scanner)
    libvmintgr.asset_extraction(scanner)
    libvmintgr.escalate_vulns(vmconfig.escdir, scanner,
        vmconfig.escalate_vulns, vmconfig.escalate_compliance)
    libvmintgr.escalate_hints(vmconfig.escdir, scanner,
        vmconfig.escalate_hints, vmconfig.vulnquery_where)
    
def wf_mozdef():
    libvmintgr.printd('dequeueing events to mozdef...')
    libvmintgr.mozdef_proc(vmconfig.escdir,
        vmconfig.mozdef_compliance_urls, vmconfig.mozdef_vuln_urls,
        vmconfig.mozdef_hint_urls)

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
    try:
        fcntl.lockf(pidfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        sys.stderr.write('cannot lock %s: vmintgr already running?\n' % vmconfig.pidfile)
        sys.exit(1)
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
    adumpmode = False
    sitelistmode = False
    sitesyncmode = False
    grouplistmode = False
    adhocgroupmode = False
    purgemode = False
    escmode = False
    selection = False
    vulnproc = False
    reptest = False
    mozdefmode = False
    cvemode = False
    swquerymode = False
    targetgroup = None
    hostquerymode = False
    spoolmode = False
    targethosts = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'Aabc:dDef:g:Ghmq:Rr:' + \
            'SsVtw:x:z:')
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
        elif o == '-b':
            adumpmode = True
            selection = True
        elif o == '-c':
            cvemode = True
            selection = True
            targetcve = a
        elif o == '-g':
            adhocgroupmode = True
            targetgroup = a
            selection = True
        elif o == '-q':
            swquerymode = True
            selection = True
            targetpkg = a
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
        elif o == '-x':
            hostquerymode = True
            targethosts = a
            selection = True
        elif o == '-z':
            spoolmode = True
            spoolconf = a
            selection = True

    if not selection:
        sys.stderr.write('no operation selected, see usage (-h)\n')
        sys.exit(1)

    vmconfig = libvmintgr.VMConfig(confpath)
    logfile_init(vmconfig.logfile)
    libvmintgr.set_compliance_urls(vmconfig.compliance_url,
        vmconfig.compliance_link)
    libvmintgr.set_sourcename(vmconfig.srcname)
    libvmintgr.set_send_description(vmconfig.mozdef_send_description)

    open_pidfile()

    dbbackup(vmconfig.sql_path)
    vmdbconn = libvmintgr.db_init(vmconfig.sql_path)
    vmdbconn.create()

    if vmconfig.useserviceapi:
        libvmintgr.serviceapi_init(vmconfig.serviceapihost, \
            vmconfig.serviceapicert)

    libvmintgr.load_exemptions(vmconfig.exempt_dir)
    libvmintgr.load_vulnauto(vmdbconn)

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
    elif adumpmode:
        wf_asset_dump()
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
    elif cvemode:
        wf_cvemode(targetcve)
    elif swquerymode:
        wf_swquerymode(targetpkg)
    elif adhocgroupmode:
        wf_adhocgroup(targetgroup)
    elif hostquerymode:
        wf_hostquery(targethosts)
    elif spoolmode:
        wf_spool(spoolconf)

def wrapmain():
    try:
        domain()
    except SystemExit:
        pass
    except:
        libvmintgr.printd(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    wrapmain()

sys.exit(0)
