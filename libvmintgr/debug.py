import sys

debugging = False

def setdebugging(f):
    global debugging
    debugging = f

def printd(s):
    if not debugging:
        return
    sys.stdout.write('[debug] ' + s + '\n')
