import sqlite3
import datetime
import pytz
import calendar
import time

import vuln
import debug

class VMIntDB(object):
    SVER = 1

    def __init__(self, path):
        self._path = path
        self._conn = sqlite3.connect(self._path)

    def add_version(self):
        c = self._conn.cursor()
        c.execute('''INSERT INTO status VALUES (%d)''' % self.SVER)
        self._conn.commit()
        
    def create(self):
        c = self._conn.cursor()
        c.execute('''PRAGMA foreign_keys = ON''')
        c.execute('''CREATE TABLE IF NOT EXISTS status (version INTEGER)''')
        c.execute('''SELECT MAX(version) FROM status''')
        rows = c.fetchall()

        v = rows[0][0]
        if v == None:
            self.add_version()

        c.execute('''CREATE TABLE IF NOT EXISTS assets
            (id INTEGER PRIMARY KEY, uid TEXT, nxaid INTEGER, ip TEXT,
            hostname TEXT, mac TEXT,
            UNIQUE (uid))''')

        c.execute('''CREATE TABLE IF NOT EXISTS vulns
            (id INTEGER PRIMARY KEY, nxvid INTEGER,
            title TEXT, cvss REAL,
            UNIQUE(nxvid))''')

        c.execute('''CREATE TABLE IF NOT EXISTS assetvulns
            (id INTEGER PRIMARY KEY, aid INTEGER, vid INTEGER,
            detected INTEGER,
            UNIQUE (aid, vid),
            FOREIGN KEY(aid) REFERENCES assets(id),
            FOREIGN KEY(vid) REFERENCES vulns(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS workflow
            (id INTEGER PRIMARY KEY, vid INTEGER,
            lasthandled INTEGER, contact INTEGER,
            status INTEGER,
            FOREIGN KEY(vid) REFERENCES assetvulns(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS cves
            (id INTEGER PRIMARY KEY, vid INTEGER, cve TEXT,
            UNIQUE (vid, cve),
            FOREIGN KEY (vid) REFERENCES vulns(id))''')

        c.execute('''CREATE TABLE IF NOT EXISTS rhsas
            (id INTEGER PRIMARY KEY, vid INTEGER, rhsa TEXT,
            UNIQUE (vid, rhsa),
            FOREIGN KEY (vid) REFERENCES vulns(id))''')

    def add_references(self, v, vid):
        c = self._conn.cursor()

        if v.cves != None:
            for cve in v.cves:
                c.execute('''INSERT INTO cves VALUES (NULL,
                    %s, "%s")''' % (vid, cve))
        if v.rhsa != None:
            for rhsa in v.rhsa:
                c.execute('''INSERT INTO rhsas VALUES (NULL,
                    %s, "%s")''' % (vid, rhsa))
        self._conn.commit()
            
    def expire_hosts(self, foundlist):
        c = self._conn.cursor()

        c.execute('''SELECT id, uid FROM assets''')
        rows = c.fetchall()
        for i in rows:
            if i[1] not in foundlist:
                self.remove_asset(i[0])
    
    def remove_asset(self, assetid):
        c = self._conn.cursor()

        debug.printd('removing database asset id %d' % assetid)
        c.execute('''DELETE FROM workflow WHERE vid IN
            (SELECT id FROM assetvulns WHERE aid = %d)''' % assetid)
        c.execute('''DELETE FROM assetvulns WHERE aid = %d''' % assetid)
        c.execute('''DELETE FROM assets WHERE id = %d''' % assetid)
        self._conn.commit()

    def add_vuln_master(self, v):
        c = self._conn.cursor()
        exists = False
        ret = None

        try:
            c.execute('''INSERT INTO vulns VALUES (NULL,
                %s, "%s", %f)''' % (v.vid, v.title, v.cvss))
        except sqlite3.IntegrityError:
            exists = True
 
        if exists:
            c.execute('''SELECT id FROM vulns WHERE nxvid=%s''' % v.vid)
            rows = c.fetchall()
            if len(rows) == 0:
                raise Exception('fatal error requesting vulns entry')
            return rows[0][0]

        ret = c.lastrowid
        self.add_references(v, ret)
        self._conn.commit()
        return ret

    def add_vulnerability(self, v, dbassetid):
        c = self._conn.cursor()

        c.execute('''SELECT assetvulns.id FROM assetvulns
            JOIN vulns on assetvulns.vid = vulns.id
            WHERE vulns.nxvid = %s AND assetvulns.aid = %d''' % \
            (v.vid, dbassetid))
        rows = c.fetchall()
        # XXX If the issue doesn't exist add it, maybe we should also
        # update the discovery value if it already existed and the current
        # value does not match the value in v.discovered_date_unix
        if len(rows) == 0:
            # This is a new issue for this asset
            vulnrow = self.add_vuln_master(v)
            c.execute('''INSERT INTO assetvulns VALUES (NULL, %d,
                %s, %d)''' % (dbassetid, vulnrow,
                v.discovered_date_unix))
            entrow = c.lastrowid
            c.execute('''INSERT INTO workflow VALUES (NULL, %s,
                0, %d, 0)''' % (entrow, int(calendar.timegm(time.gmtime()))))
        else:
            c.execute('''UPDATE assetvulns SET detected = %d WHERE
                id = %d''' % (v.discovered_date_unix, rows[0][0]))
        self._conn.commit()

    def add_asset(self, uid, aid, address, mac, hostname):
        c = self._conn.cursor()
        c.execute('''SELECT id FROM assets WHERE uid="%s"''' % uid)
        rows = c.fetchall()
        if len(rows) == 0:
            c.execute('''INSERT INTO assets VALUES (NULL, "%s", %d,
                "%s", "%s", "%s")''' % (uid, aid, address, hostname, mac))
            self._conn.commit()
            return c.lastrowid
        else:
            return rows[0][0]

def db_init(path):
    ret = VMIntDB(path)
    return ret
