#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################
#  Server.py - (?)
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

from gevent import select, monkey, spawn, Greenlet, GreenletExit, sleep, socket
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
                buffer = self.srecv()
                print ">>",buffer
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
