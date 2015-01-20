#!/usr/bin/python2

import sys

def domain():
    if len(sys.argv) != 4:
        sys.stdout.write('usage: hfuzz-add.py vulnauto hfuzzout groupmatch\n')
        sys.exit(0)

    vaf = sys.argv[1]
    hfo = sys.argv[2]
    grp = sys.argv[3]

    fd = open(vaf, 'r')
    buf = fd.readlines()
    fd.close()

    hfd = open(hfo, 'r')

    idx = 0
    for i in buf:
        if 'namematch =' in i:
            break
        idx += 1

    firstent = False
    s = buf[idx].split()
    if len(s) == 2:
        firstent = True
    else:
        idx += 1
        for i in buf[idx:]:
            if '=' in i:
                break
            idx += 1

    autoadd = False
    while True:
        tmp = hfd.readline()
        if tmp == None or tmp == '':
            break
        el = tmp.strip().split()
        if len(el) != 4:
            continue
        if el[2] != grp:
            continue
        if firstent:
            buf[idx] = 'namematch = #AUTOADD\n'
            autoadd = True
            idx += 1
            buf.insert(idx, '\t%s\n' % el[0])
            firstent = False
        else:
            if not autoadd:
                buf.insert(idx, '\t#AUTOADD\n')
                idx += 1
                autoadd = True
            buf.insert(idx, '\t%s\n' % el[0])

    sys.stdout.write(''.join(buf))

if __name__ == '__main__':
    domain()

sys.exit(0)
