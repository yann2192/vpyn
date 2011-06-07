#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

import sys, os
import sqlite3
from hashlib import sha256
from base64 import b64encode, b64decode
from gevent import sleep
from xml.dom.minidom import Document, parseString
from Config import *

class Index:
    def __init__(self, id):
        self.db = sqlite3.connect(os.path.join(indexfolder,id.encode('hex')))
        try:
            self.create_index()
        except:
            pass
    
    def create_index(self):
        try:
            c = self.db.cursor()
            c.execute('CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, size INTEGER)')
            self.db.commit()
        finally:
            c.close()

    def list_index(self):
        c = self.db.cursor()
        res = []
        try:
            c.execute('SELECT * FROM files')
            self.db.commit()
            for i in c:
                res.append(i)
        finally:
            c.close()
            return res

    def get_file_by_id(self, id):
        c = self.db.cursor()
        res = None
        try:
            c.execute('SELECT * FROM files WHERE id="%d"' % id)
            self.db.commit()
            res = c.fetchone()
        except:
            pass
        
        finally:
            c.close()
            return res

    def get_xml(self):
        buff = self.list_index()
        res = Document()
        xml = res.createElement("index")
        for i in buff:
            sleep(0)
            file = res.createElement("file")
            file.setAttribute("id", str(i[0]))
            file.setAttribute("name", i[1])
            file.setAttribute("size", str(i[2]))
            xml.appendChild(file)
        res.appendChild(xml)
        return res.toxml()

    def set_xml(self, xml):
        c = self.db.cursor()
        try:
            c.execute('DELETE FROM files WHERE 1=1')
            self.db.commit()
            xml = parseString(xml)
            index = xml.getElementsByTagName("file")
            for i in index:
                sleep(0)#.0001)
                c.execute('INSERT INTO files VALUES(%d, "%s", %d)' % (int(i.getAttribute("id")), i.getAttribute("name"), int(i.getAttribute("size"))))
        finally:
            self.db.commit()
            c.close()        

class MyIndex(Index):
    def __init__(self):
        self.db = sqlite3.connect(myindex)        
        try:
            self.create_index()
        except:
            pass
        try:
            self.create_folderindex()
        except:
            pass

    
    def create_index(self):
        try:
            c = self.db.cursor()
            c.execute('CREATE TABLE files (id INTEGER PRIMARY KEY, name TEXT, size INTEGER, path TEXT, folder INTEGER)')
            self.db.commit()
        finally:
            c.close()

    def create_folderindex(self):
        c = self.db.cursor()
        try:
            c.execute('CREATE TABLE folders (id INTEGER PRIMARY KEY, name TEXT UNIQUE)') 
            self.db.commit()
        finally:
            c.close()

    def get_index(self):
        c = self.db.cursor()
        res = []
        try:
            c.execute('SELECT * FROM folders')
            self.db.commit()
            for i in c:
                res.append(i)
        finally:
            c.close()
            return res

    def add_files(self, path, num, callback, db = None):
        if db == None:
            c = self.db.cursor()
        else:
            c = db
        try:
            list = os.listdir(path)
            for i in list:
                try:
                    sleep(0)
                    abs = os.path.join(path,i)
                    if os.path.isdir(abs):
                        self.add_files(abs, num, callback)
                    else:
                        size = os.path.getsize(abs)
                        id = os.stat(abs).st_ino
                        if id == 0:
                            id = int(os.urandom(4).encode('hex'), 16)
                        c.execute('INSERT INTO files VALUES(%d, "%s", %d, "%s", %d)' % (id, os.path.basename(abs), size, abs, num))
                        if callback is not None:
                            callback.add()
                except KeyboardInterrupt:
                    raise
                except:
                    pass
        finally:
            if db == None:
                self.db.commit()
                c.close()

    def add_folder(self, path, callback=None):
        c = self.db.cursor()
        try:
            path = os.path.abspath(path)
            if os.path.exists(path) is False:
                raise Exception, "%s not found" % path
            try:
                c.execute('INSERT INTO folders VALUES(NULL, "%s")' % path)
                self.db.commit()
            except:
                pass
            c.execute('SELECT id FROM folders WHERE name="%s"' % path)
            self.db.commit()
            id = c.fetchone()[0]
            self.add_files(path, id, callback)
        finally:
            c.close()

    def rm_folder_by_id(self, id):
        c = self.db.cursor()
        try:
            c.execute('DELETE FROM files WHERE folder=%d' % id)
            self.db.commit()
            res = c.rowcount
            c.execute('DELETE FROM folders WHERE id=%d' % id)
            self.db.commit()
            return res
        finally:
            c.close()
