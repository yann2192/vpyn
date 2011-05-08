#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

import sys, os
from gevent import select, monkey, spawn, Greenlet, GreenletExit, sleep, socket
from base64 import b64encode
from hashlib import md5
from struct import pack, unpack
from zlib import adler32
from Proto import Proto
from Index import Index
from Config import *

class Client(Proto):
    def __init__(self, vpn):
        self.vpn = vpn

    def close(self):
        try:
            self.sock.close()
        except:
            pass

    def error(self, exp):
        self.close()

    def connect(self, host, port, pubkey):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            self.handshake(pubkey)
        except Exception as e:
            self.error(e)
            raise

    def handshake(self, pubkey):
        self.send_id()
        myiv = self.send_iv()
        iv = self.get_iv(pubkey)
        self.init_cipher(pubkey, myiv, iv)

    def recv_file(self):
        if self.srecvall(1) != "\x01":
            self.ssend("\xFF")
            raise Exception, "Bad Flags (0x01 expected)"
        size = self.srecvall(4)
        checksum = self.srecvall(4)
        if adler32(size) != unpack('!I',checksum)[0]:
            self.ssend("\xFF")
            raise Exception, "Bad checksum"
        size = unpack('!I', size)[0]
        buffer = self.srecvall(size)
        hash = self.srecvall(16)
        if md5(buffer).digest() != hash:
            self.ssend("\xFF")
            raise Exception, "Bad md5 ..."
        return buffer

    def get_file(self, id, name):
        path = os.path.join(inbox, name)
        while os.path.exists(path):
            name = "_"+name
            path = os.path.join(inbox, name)
            #raise Exception, "%s already exist ..." % path
        self.ssend("\x02"+pack('!I',id))
        buff = self.recv_file()
        with open(path, "wb") as f:
            f.write(buff)

    def get_index(self, id):
        index = Index(id)
        buffer = index.get_xml().encode('utf-8')
        hash = md5(buffer).digest()
        self.ssend('\x03'+hash)
        flag = self.srecvall(1)
        if flag == "\x04":
            buffer = self.recv_file()
            index.set_xml(buffer)
        elif flag == "\x05":
            pass
        else:
            raise Exception, "Protocol Error"
