# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys

import debug

def asset_gid_scan_set(scanner, gid, window_start, window_end):
    squery = '''
    SELECT asset_id, scan_id, scan_finished
    FROM fact_asset_date('%s', '%s', INTERVAL '1 day')
    WHERE asset_id IN
    (SELECT asset_id FROM dim_asset_group_asset
    WHERE asset_group_id = %s)
    ''' % (window_start, window_end, gid)

    sites = scanner.sitelist.keys()
    if len(sites) == 0:
        return

    debug.printd('building asset gid scan set')
    ret = scanner.conn.adhoc_report(squery, sites, api_version='1.3.2')
