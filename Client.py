#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################
#  Client.py - (?)
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

class Client(Proto):
    def __init__(self, vpn):
        self.vpn = vpn

    def error(self, exp):
        try:
            self.sock.close()
        except: 
            pass

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

