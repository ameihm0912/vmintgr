#!/usr/bin/python

import sys
import getopt
import libvmintgr
import json

import pyservicelib as slib

def usage():
    sys.stdout.write('usage: grouptest.py [-hj] [-f path] (ip|host):string\n')

confpath = None
jsonoutput = False

try:
    opts, args = getopt.getopt(sys.argv[1:], 'f:hj')
except getopt.GetoptError as e:
    sys.stderr.write(str(e) + '\n')
    usage()
    sys.exit(1)
for o, a in opts:
    if o == '-h':
        usage()
        sys.exit(0)
    elif o == '-f':
        confpath = a
    elif o == '-j':
        jsonoutput = True
if len(args) != 1:
    usage()
    sys.exit(1)

vmconfig = libvmintgr.VMConfig(confpath)

if vmconfig.useserviceapi:
    libvmintgr.serviceapi_init(vmconfig.serviceapihost, \
        vmconfig.serviceapicert)
else:
    sys.stderr.write('unable to proceed if serviceapi is disabled\n')
    sys.exit(1)

s = args[0].split(':')
if len(s) != 2:
    usage()
    sys.exit(1)
if s[0] == 'ip':
    sys.stderr.write('ip lookup currently not supported\n')
    sys.exit(1)
elif s[0] == 'host':
    matchhost = s[1]
else:
    usage()
    sys.exit(1)

# Currently only do host lookups using serviceapi here
ns = slib.Search()
ns.add_host(matchhost)
ns.execute()
ret = ns.result_host(matchhost)
tn = 'default'
if ret != None:
    if 'owner' in ret and 'team' in ret['owner']:
        tn = ret['owner']['team']

if not jsonoutput:
    sys.stdout.write('%s -> %s\n' % (args[0], tn))
else:
    nd = {}
    enam = s[0]
    nd[enam] = s[1]
    nd['team'] = tn
    sys.stdout.write('%s' % json.dumps(nd))

sys.exit(0)
