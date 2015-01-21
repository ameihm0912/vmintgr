#!/usr/bin/python2

import sys
import pyes
import getopt

es = None
index = 'vulnerability'

MODE_UNSET  = 0
MODE_LIST   = 1
MODE_CREATE = 2
MODE_DELETE = 3

def usage():
    sys.stdout.write('usage: indexmgr.py [-cdh] [-e eshost]\n')
    sys.exit(0)

def domain():
    global es

    opmode = MODE_UNSET
    eshost = None
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'cde:h')
    except getopt.GetoptError as e:
        sys.stderr.write(str(e) + '\n')
        usage()
    for o, a in opts:
        if o == '-h':
            usage()
        elif o == '-c':
            opmode = MODE_CREATE
        elif o == '-d':
            opmode = MODE_DELETE
        elif o == '-e':
            eshost = a

    if opmode == MODE_UNSET:
        opmode = MODE_LIST

    if eshost == None:
        sys.stderr.write('error: eshost must be specified with -e\n')
        sys.exit(1)
    es = pyes.ES(('http', eshost, '9200'))

    if opmode == MODE_LIST:
        idx = es.indices.get_indices()
        for i in idx:
            sys.stdout.write('%s %d\n' % (i, idx[i]['num_docs']))
    elif opmode == MODE_CREATE:
        es.indices.create_index(index)
    elif opmode == MODE_DELETE:
        es.indices.delete_index(index)

if __name__ == '__main__':
    domain()

sys.exit(0)
