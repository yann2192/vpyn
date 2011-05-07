#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from gevent import select, monkey, spawn, Greenlet, GreenletExit, sleep, socket
from hashlib import md5
from struct import pack, unpack
from zlib import adler32
from Proto import Proto

class Server(Greenlet):
    handlers = []
    def __init__(self, port, vpn):
        Greenlet.__init__(self)
        self.vpn = vpn
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('',port))
        self.sock.listen(5)
        self.start()
        
    def _run(self):
        try:
            while True:
                sock, addr = self.sock.accept()
                self.handlers.append(ServerHandler(sock, self.vpn))
        except Exception as e:
            self.error(e)

    def error(self, exp):
        self.end()

    def end(self):
        self.sock.close()
        for i in self.handlers:
            i.kill(block=True)
        raise GreenletExit

class ServerHandler(Greenlet, Proto):
    def __init__(self, sock, vpn):
        Greenlet.__init__(self)
        self.vpn = vpn
        self.sock = sock
        self.start()
        
    def _run(self):
        try:
            self.handshake()
            while True:
                self.loop()
        except Exception as e:
            self.error(e)

    def end(self):
        self.sock.close()
        raise GreenletExit

    def error(self, exp):
        self.end()

    def handshake(self):
        pubkey = self.check_id()
        iv = self.get_iv(pubkey)
        myiv = self.send_iv()
        self.init_cipher(pubkey, myiv, iv)

    def loop(self):
        buff = self.srecv(1)
        if buff == "\x02":
            self.request_for_file()
        elif buff == "\x03":
            self.request_for_index()

    def request_for_file(self):
        id = unpack('!I',self.srecvall(4))[0]
        path = self.vpn.index.get_file_by_id(id)[3]
        self.send_file(path)

    def send_file(self, path):
        if not os.path.exists(path) or not os.path.isfile(path):
            self.ssend("\xFF")
            raise Exception, "Bad file"
        size = pack('!I', os.path.getsize(path))
        checksum = pack('!I', adler32(size))
        ctx = md5()
        self.ssend("\x01"+size+checksum)
        with open(path,'rb') as f:
            while True:
                sleep(0)
                buff = f.read(4096)
                if buff == "":
                    break
                ctx.update(buff)
                self.ssend(buff)
        self.ssend(ctx.digest())

    def request_for_index(self):
        tmp = self.srecvall(16)
        index = self.vpn.index.get_xml().encode('utf-8')
        hash = md5(index).digest()
        if hash == tmp:
            self.ssend("\x05")
        else:
            size = pack('!I', len(index))
            checksum = pack('!I', adler32(size))
            self.ssend("\x04\x01"+size+checksum+index+hash)
