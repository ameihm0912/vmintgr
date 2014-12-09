import sqlite3

import vuln

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
        c.execute('''CREATE TABLE IF NOT EXISTS status (version INTEGER)''')
        c.execute('''SELECT MAX(version) FROM status''')
        rows = c.fetchall()

        v = rows[0][0]
        if v == None:
            self.add_version()

        c.execute('''CREATE TABLE IF NOT EXISTS assets
            (id INTEGER PRIMARY KEY, uid TEXT, aid INTEGER, ip TEXT,
            hostname TEXT, mac TEXT)''')

        c.execute('''CREATE TABLE IF NOT EXISTS vulns
            (id INTEGER PRIMARY KEY, asset INTEGER,
            vid INTEGER, title TEXT, cvss REAL,
            FOREIGN KEY(asset) REFERENCES assets(id))''')

    def add_vulnerability(self, v, dbassetid):
        c = self._conn.cursor()
        c.execute('''SELECT id, asset, vid, cvss FROM vulns
            WHERE asset=%d AND vid=%s''' % (dbassetid, v.vid))
        rows = c.fetchall()
        if len(rows) == 0:
            # This is a new issue for this asset
            c.execute('''INSERT INTO vulns VALUES (NULL, %d,
                %s, "%s", %f)''' % (dbassetid, v.vid,
                v.title, v.cvss))
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
