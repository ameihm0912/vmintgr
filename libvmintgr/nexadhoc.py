# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys

import debug

def nexpose_adhoc(scanner, squery, sites, api_version=None):
    if api_version != None:
        return scanner.conn.adhoc_report(squery, sites,
            api_version=api_version)
    else:
        return scanner.conn.adhoc_report(squery, sites)
