# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import os
import calendar
import time
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
try:
    import cPickle
except ImportError:
    import pickle as cPickle
import re
from netaddr import *

import pyservicelib

import libvmintgr.debug as debug
import libvmintgr.sql as sql
import libvmintgr.vmjson as vmjson
import libvmintgr.services as services

defaultvulnauto = None
vulnautolist = []
uidcache = []
dbconn = None

# XXX This should probably be in a configuration file
class ComplianceLevels(object):
    ORDERING = ('maximum', 'high', 'mediumlow')
    LEVELS = {
        # 1 day
        'maximum': 1.0,
        # 1 week
        'high': 7.0,
        # 1 month
        'mediumlow': 30.0
    }
    FLOOR = {
        'maximum': 9.0,
        'high': 7.0,
        'mediumlow': 5.0
    }

class VulnAutoEntry(object):
    pri_adjust = {
            0: 9,
            1: 8,
            2: 7,
            3: 6,
            4: 5,
            5: 4,
            6: 3,
            7: 2,
            8: 1,
            9: 0
        }

    def __init__(self, name):
        self.name = name
        self.title = None
        self.description = None
        self.mincvss = None

        self._match_ip = []
        self._match_net = []
        self._match_name = []

    def add_match(self, val, pri):
        if '/' in val:
            self._match_net.append((IPNetwork(val), pri))
        else:
            self._match_ip.append((IPAddress(val), pri))

    def add_namematch(self, val, pri):
        self._match_name.append((re.compile(val), pri))

    def name_test(self, hostname):
        best = -1
        for i in self._match_name:
            if i[0].match(hostname):
                cur = 75 + self.pri_adjust[i[1]]
                if cur > best:
                    best = cur
        return best

    def ip_test(self, ipstr):
        ip = IPAddress(ipstr)

        # First try the IP
        for i in self._match_ip:
            if i[0] == ip:
                return 100 + self.pri_adjust[i[1]]

        best = -1
        for i in self._match_net:
            if ip in i[0]:
                cur = i[0].netmask.bits().count('1')
                cur += self.pri_adjust[i[1]]
                if cur > best:
                    best = cur
        return best

class WorkflowElement(object):
    STATUS_NONE = 0
    STATUS_ESCALATED = 1
    STATUS_RESOLVED = 2
    STATUS_CLOSED = 3

    def __init__(self):
        self.workflow_id = None
        self.assetid_site = None
        self.vulnerability = None
        self.lasthandled = None
        self.contact = None
        self.status = None

class ComplianceElement(object):
    def __init__(self):
        self.compliance_id = None
        self.failed = None
        self.lasthandled = None
        self.failvuln = None

class vulnerability(object):
    def __init__(self):
        self.sitename = None
        self.assetid = None
        self.ipaddr = None
        self.hostname = None
        self.macaddr = None
        self.os = None
        self.title = None
        self.description = None
        self.discovered_date = None
        self.discovered_date_unix = None
        self.age_days = None
        self.patch_in = None
        self.cves = None
        self.cvss = None
        self.cvss_vector = None
        self.impact_label = None
        self.likelihood_indicator = None
        self.rhsa = None
        self.vid = None
        self.vid_classified = None
        self.known_exploits = None
        self.known_malware = None
        self.autogroup = None
        self.proof = None

    def __str__(self):
        buf = '----- %d %s | %s | %s\n' \
            'sitename: %s\n' \
            'hostname: %s\n' \
            'macaddr: %s\n' \
            'discovered: %s\n' \
            '----' % (self.assetid, self.ipaddr, self.title, self.vid,
                self.sitename, self.hostname, self.macaddr,
                self.discovered_date)
        return buf

def cvss_to_label(cvss):
    for i in ComplianceLevels.ORDERING:
        if cvss >= ComplianceLevels.FLOOR[i]:
            return i
    if cvss >= 0:
        return 'mediumlow'
    return 'unknown'

def cvss_to_patch_in(cvss):
    for i in ComplianceLevels.ORDERING:
        if cvss >= ComplianceLevels.FLOOR[i]:
            break
    return ComplianceLevels.LEVELS[i]

def vuln_reset_uid_cache():
    global uidcache
    uidcache = []

def resolve_expired_hosts():
    dbconn.resolve_expired_hosts(uidcache)

def sitelist_get_os(aid, scanner):
    for s in scanner.sitelist.keys():
        for a in scanner.sitelist[s]['assets']:
            if a['id'] == aid:
                return a['os']
    return None

def escalate_vulns(escdir, scanner, escalate_vulns, escalate_compliance):
    ret = dbconn.asset_list()
    debug.printd('processing %d assets' % len(ret))
    vlist = []

    for i in ret:
        wfes = dbconn.get_workflow(i)

        for w in wfes:
            if w.status == WorkflowElement.STATUS_NONE:
                w.status = WorkflowElement.STATUS_ESCALATED
            elif w.status == WorkflowElement.STATUS_RESOLVED:
                w.status = WorkflowElement.STATUS_CLOSED

            w.vulnerability.os = sitelist_get_os(w.assetid_site, scanner)

            # Assign a risk likelihood indicator value to the event. We
            # default to MEDIUM. HIGH and MAXIMUM are reserved for issues
            # that are manually flagged as such, which this tool does not
            # currently support handling.
            w.vulnerability.likelihood_indicator = 'medium'

            # Create JSON event from the element
            jv = vmjson.wf_to_json(w)
            vlist.append(jv)

            # Mark this workflow element as handled now
            dbconn.workflow_handled(w.workflow_id, w.status)

    # Send coverage indicators
    services.send_indicators(scanner)

    vlist = services.serviceapi_vulnlist(vlist)
    if len(vlist) > 0:
        if escalate_vulns:
            write_vuln_escalations(vlist, escdir)

    clist = []
    # Do the same thing for compliance items
    for i in ret:
        ce = dbconn.get_compliance(i)
        # get_compliance returning None means the system passed compliance
        # checks, we still want to create an event though.

        if ce == None:
            target = dbconn.aid_to_host(i)
            autogroup = dbconn.aid_to_autogroup(i)
        else:
            target = ce.failvuln.hostname
            autogroup = ce.failvuln.autogroup

        jc = vmjson.ce_to_json(ce, target, autogroup)
        clist.append(jc)

    clist = services.serviceapi_complist(clist)
    if len(clist) > 0:
        if escalate_compliance:
            write_compliance_escalations(clist, escdir)

def write_compliance_escalations(clist, escdir):
    fname = 'compliance-%d-%d.dat' % (int(calendar.timegm(time.gmtime())),
        os.getpid())
    outfile = os.path.join(escdir, fname)
    tmpoutfile = outfile + '.tmp'
    debug.printd('writing compliance escalations to %s' % outfile)

    fd = open(tmpoutfile, 'w')
    cPickle.dump(clist, fd)
    fd.close()
    os.rename(tmpoutfile, outfile)

def write_vuln_escalations(vlist, escdir):
    fname = 'vulns-%d-%d.dat' % (int(calendar.timegm(time.gmtime())),
        os.getpid())
    outfile = os.path.join(escdir, fname)
    tmpoutfile = outfile + '.tmp'
    debug.printd('writing vulnerabilities escalations to %s' % outfile)

    fd = open(tmpoutfile, 'w')
    cPickle.dump(vlist, fd)
    fd.close()
    os.rename(tmpoutfile, outfile)

def asset_unique_id(address, mac, hostname, aid):
    if mac == '':
        u_mac = 'NA'
    else:
        u_mac = mac
    if hostname == '':
        u_hostname = 'NA'
    else:
        u_hostname = hostname
    ret = '0|%s|%s|%s|%s' % (aid, address, u_hostname, u_mac)
    debug.printd('using identifier %s' % ret)
    return ret

def calculate_compliance(uid):
    debug.printd('calculating compliance for %s' % uid)
    ret = dbconn.compliance_values(uid)

    failvid = None
    failage = 0
    max_cvss = 0
    for level in ComplianceLevels.ORDERING:
        for val in ret:
            vid = val[0]
            cvss = val[1]
            age = val[2]
            if cvss >= ComplianceLevels.FLOOR[level] and \
                age > ComplianceLevels.LEVELS[level]:
                # Compliance failure, note the vulnerability that caused the
                # failure that has the highest CVSS base score
                if failvid == None or max_cvss < cvss:
                    failvid = vid
                    max_cvss = cvss
                    failage = age
        if failvid != None:
            break

    failflag = False
    if failvid != None:
        debug.printd('asset fails compliance due to vid %d '
            '(cvss=%f, age=%d)' % (failvid, max_cvss, failage))
        failflag = True

    dbconn.compliance_update(uid, failflag, failvid)

def vuln_auto_finder(address, mac, hostname):
    candlist = None
    last = -1
    cand = None
    for va in vulnautolist:
        ret = va.name_test(hostname)
        if ret != -1:
            if ret > last:
                cand = va
                last = ret

        ret = va.ip_test(address)
        if ret == -1:
            continue
        if ret > last:
            cand = va
            last = ret
    if cand != None:
        debug.printd('using VulnAutoEntry %s (score: %d)' % (cand.name, last))
    else:
        debug.printd('using default vulnauto entry')
        cand = defaultvulnauto
    return cand

def vuln_cvereport(asset, targetcve):
    addr = asset['address']
    mac = asset['macaddress']
    hostname = asset['hostname']

    if hostname == '':
        hostname = 'unknown'

    for v in asset['vulns']:
        if v.cves == None:
            continue
        match = False
        matchcve = None
        for c in v.cves:
            if re.match(targetcve, c) != None:
                match = True
                matchcve = c
                break
        if not match:
            continue
        sys.stdout.write('%s %s %s %s %s\n' % \
            (hostname, addr, mac, c, v.title))

def vuln_hostreport(asset):
    addr = asset['address']
    mac = asset['macaddress']
    hostname = asset['hostname']

    if hostname == '':
        hostname = 'unknown'

    for v in asset['vulns']:
        if v.cves != None and len(v.cves) > 0:
            cvebuf = ','.join(v.cves)
        else:
            cvebuf = '-'

        if len(mac) == 0:
            mac = '-'

        impactlabel = cvss_to_label(v.cvss)
        sys.stdout.write('%s %s %s %s %.2f %s %s proof[%s]\n' % \
            (hostname, addr, mac, cvebuf, v.cvss, impactlabel, v.title, v.proof))

def vuln_proc_pipeline(vlist, aid, address, mac, hostname):
    global uidcache
    vidcache = []

    debug.printd('vulnerability process pipeline for asset id %d' % aid)
    vauto = vuln_auto_finder(address, mac, hostname)
    if vauto == -1:
        debug.printd('skipping pipeline for asset id %d, no handler' % aid)
        return

    uid = asset_unique_id(address, mac, hostname, aid)
    if uid not in uidcache:
        uidcache.append(uid)

    dbconn.asset_search_and_update(uid, aid, address, mac, hostname)

    # Make sure the asset exists in the database, if not add it
    dbassetid = dbconn.add_asset(uid, aid, address, mac, hostname)
    if dbassetid == None:
        # The asset wasn't added, probably because it is a duplicate of another
        # asset, if this happens we are done
        return
    debug.printd('using db asset %d' % dbassetid)

    for v in vlist:
        vidcache.append(int(v.vid))
        # We don't want to look at everything, query the handlers minimum
        # CVSS value to see if we should proceed
        if v.cvss >= vauto.mincvss:
            debug.printd('processing vulnerability %s' % v.vid)
            dbconn.add_vulnerability(v, dbassetid, vauto)
        else:
            debug.printd('skipping vulnerability %s as it does not meet ' \
                'minimum cvss score' % v.vid)

    dbconn.resolve_vulnerability(vidcache, dbassetid)

    # Calculate the compliance score for the asset
    calculate_compliance(uid)

def load_vulnauto(vmdbconn):
    global dbconn
    global defaultvulnauto
    dbconn = vmdbconn

    debug.printd('adding default vulnauto entry')
    defaultvulnauto = VulnAutoEntry('default')
    defaultvulnauto.title = 'default'
    defaultvulnauto.mincvss = 6.0
    defaultvulnauto.description = 'default'

    debug.printd('requesting automation data from service api')
    vad = pyservicelib.get_vulnauto()

    for i in vad['vulnauto']:
        ne = VulnAutoEntry(str(i['v2bkey']))
        ne.mincvss = 6.0
        ne.title = str(i['v2bkey'])
        ne.description = ne.title
        ne.add_namematch(str(i['match']), 1)
        vulnautolist.append(ne)
