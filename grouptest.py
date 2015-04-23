#!/usr/bin/python

import sys
import getopt
import libvmintgr

def usage():
    sys.stdout.write('usage: grouptest.py [-h] [-f path] (ip|host):string\n')

confpath = None

try:
    opts, args = getopt.getopt(sys.argv[1:], 'f:h')
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
if len(args) != 1:
    usage()
    sys.exit(1)

vmconfig = libvmintgr.VMConfig(confpath)
libvmintgr.load_vulnauto(vmconfig.vulnauto_dir, None)

matchip = '0.0.0.0'
matchhost = ''

s = args[0].split(':')
if len(s) != 2:
    usage()
    sys.exit(1)
if s[0] == 'ip':
    matchip = s[1]
elif s[0] == 'host':
    matchhost = s[1]
else:
    usage()
    sys.exit(1)

v = libvmintgr.vuln_auto_finder(matchip, '', matchhost)
sys.stdout.write('%s -> %s\n' % (args[0], v.name))

sys.exit(0)
