import sys

dhook = None
debugging = False

def setdebugging(f):
    global debugging
    debugging = f

def register_hook(f):
    global dhook
    dhook = f

def printd(s):
    if dhook != None:
        dhook(s)
    if not debugging:
        return
    sys.stdout.write('[debug] ' + s + '\n')
