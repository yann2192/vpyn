#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################
#  Manage.py - (?)
#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
########################################################################

import sys, os
import sqlite3
from hashlib import sha512, sha256
from base64 import b64encode, b64decode
from gevent import sleep
from Crypto import *

home = os.getenv('USERPROFILE') or os.getenv('HOME')
database = '.VPyN.db'
keyfile = 'key.aes'

class Manage():
    def __init__(self, pwd):
        self.db = sqlite3.connect(database)
        if os.path.exists(keyfile):
            if os.path.getsize(keyfile) != 296: raise Exception, "File key.aes is corrupted !"
            with open(keyfile, 'rb') as f:
                iv = f.read(16)
                hash = f.read(64)
                privkey = f.read(72)
                privkey = aes(pwd, iv, 0).ciphering(privkey)
                if sha512(privkey).digest() != hash: raise Exception, "Bad key ..."
                pubkey_x = f.read(72)
                pubkey_y = f.read(72)
                self.ecc = ECC_key(pubkey_x, pubkey_y, privkey)
                print "[+] ECC key loaded"
        else:
            with open(keyfile, 'wb') as f:
                self.ecc = ECC_key()
                iv = os.urandom(16)
                f.write(iv)
                f.write(sha512(self.ecc.privkey).digest())
                f.write(aes(pwd, iv, 1).ciphering(self.ecc.privkey))
                f.write(self.ecc.pubkey_x+self.ecc.pubkey_y)
                print "[+] ECC key created"

    def connectTo(self, host, port, pubkey_x, pubkey_y):
        res = FactClt(vpn, (pubkey_x,pubkey_y))
        reactor.connectTCP(host, port, res)
        return res

    def create_peers(self):
        c = self.db.cursor()
        c.execute('CREATE TABLE peers (num INTEGER PRIMARY KEY, id BLOB UNIQUE, nick TEXT UNIQUE, host TEXT, port INTEGER, pubkey_x BLOB, pubkey_y BLOB)')
        self.db.commit()

    def add_peer(self, nick, host, port, pubkey_x, pubkey_y):
        c = self.db.cursor()
        try:
            c.execute('INSERT INTO peers VALUES(NULL, "%s", "%s", "%s", "%d", "%s", "%s")' % (b64encode(sha256(pubkey_x+pubkey_y).digest()), nick, host, port, b64encode(pubkey_x), b64encode(pubkey_y)))
            self.db.commit()
        except:
            self.create_peers()
            c.execute('INSERT INTO peers VALUES(NULL, "%s", "%s", "%s", "%d", "%s", "%s")' % (b64encode(sha256(pubkey_x+pubkey_y).digest()), nick, host, port, b64encode(pubkey_x), b64encode(pubkey_y)))
            self.db.commit()
        finally:
            c.close()

    def get_pubkey_by_id(self, id):
        c = self.db.cursor()
        try:
            c.execute('SELECT * FROM peers WHERE id="%s"' % b64encode(id))
            self.db.commit()
            res = c.fetchone()
            return (b64decode(res[5]), b64decode(res[6]))

        except:
            return None
        
        finally:
            c.close()

    def get_peer_by_id(self, id):
        c = self.db.cursor()
        try:
            c.execute('SELECT * FROM peers WHERE id="%s"' % b64encode(id))
            self.db.commit()
            res = c.fetchone()
            return (b64decode(res[1]), res[2], res[3], res[4], b64decode(res[5]), b64decode(res[6]))

        except:
            return None
        
        finally:
            c.close()

    def get_peer_by_num(self, num):
        c = self.db.cursor()
        try:
            c.execute('SELECT * FROM peers WHERE num=%d' % num)
            self.db.commit()
            res = c.fetchone()
            return (b64decode(res[1]), res[2], res[3], res[4], b64decode(res[5]), b64decode(res[6]))

        except:
            return None
        
        finally:
            c.close()

    def get_all_peers(self):
        c = self.db.cursor()
        res = []
        try:
            c.execute('SELECT * FROM peers')
            self.db.commit()
            for i in c:
                res.append((i[0], b64decode(i[1]), i[2], i[3], i[4], b64decode(i[5]), b64decode(i[6])))
        except:
            pass
        
        finally:
            c.close()
            return res

    def rm_peer_by_num(self, num):
        c = self.db.cursor()
        try:
            c.execute('DELETE FROM peers WHERE num=%d' % num)
            self.db.commit()
            return
        
        finally:
            c.close()

    def create_index(self):
        c = self.db.cursor()
        c.execute('CREATE TABLE _index (num INTEGER PRIMARY KEY, path TEXT UNIQUE)')
        self.db.commit()

    def add_folder(self, path):
        c = self.db.cursor()
        try:
            c.execute('INSERT INTO _index VALUES(NULL, "%s")' % path)
            self.db.commit()
        except:
            self.create_index()
            c.execute('INSERT INTO _index VALUES(NULL, "%s")' % path)
            self.db.commit()
        finally:
            c.close()

    def rm_folder_by_num(self, num):
        c = self.db.cursor()
        try:
            c.execute('DELETE FROM _index WHERE num=%d' % num)
            self.db.commit()
            return
        finally:
            c.close()

    def get_index(self):
        c = self.db.cursor()
        res = []
        try:
            c.execute('SELECT * FROM _index')
            self.db.commit()
            for i in c:
                res.append(i)
        except:
            pass
        
        finally:
            c.close()
            return res

    def list_index(self):
        res = []
        try:
            index = self.get_index()
            for i in index:
                sleep(0)
                res += self._list_index(i[1])
        finally:
            return res

    def _list_index(self, path):
        res = []
        try:
            list = os.listdir(path)
            for i in list:
                sleep(0)
                abs = os.path.join(path,i)
                if os.path.isdir(abs):
                    res += self._list_index(abs)
                else:
                    res.append(abs)
        except:
            pass
        finally:
            return res

    def get_all_files(self):
        all = self.get_all_peers()
        for i in all:
            sleep(0)
            self.connectTo(self, i[3], i[4], i[5], i[6])
