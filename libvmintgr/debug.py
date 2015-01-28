# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
