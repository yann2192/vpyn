#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################
#  Proto.py - (?)
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
from hashlib import sha512, sha256
from Crypto import *

class Proto:
    vpn = None
    sock = None
    ctx1 = None
    ctx2 = None
    Ready = False

    def check_id(self):
        id = ""
        while len(id) < 32:
            id += self.recv(32-len(id))
        pubkey = self.vpn.get_pubkey_by_id(id)
        if pubkey is None:
            raise Exception, "Unknown peer"
        return pubkey

    def send_id(self):
        self.sock.sendall(sha256(self.vpn.ecc.pubkey_x+self.vpn.ecc.pubkey_y).digest())

    def send_iv(self):
        IV = os.urandom(16) 
        tmp = IV+self.vpn.ecc.Sign(IV)
        self.sock.sendall(tmp)
        return IV

    def get_iv(self, pubkey):
        buffer = ""
        while len(buffer) < 167:
            buffer += self.recv(167-len(buffer))
        iv = buffer[0:16]
        sig = buffer[16:167]
        if ECC_key(pubkey[0], pubkey[1]).Check_sign(sig, iv) is False:
            raise Exception, "Fail to check sig"
        return iv

    def init_cipher(self, pubkey, myiv, iv):
        if len(iv) != 16 and len(myiv) != 16:
            raise Exception, "Bad IV"
        key = self.vpn.ecc.Get_EC_Key(pubkey[0], pubkey[1])
        self.ctx1 = aes(key, myiv, 1)
        self.ctx2 = aes(key, iv, 0)
        self.Ready = True

    def ssend(self, data):
        buffer = self.ctx1.ciphering(data)
        self.sock.sendall(buffer)

    def recv(self, size=4096):
        buffer = self.sock.recv(size)
        if buffer == "":
            raise Exception, "Connection lost"
        return buffer

    def srecv(self, size=4096):
        buffer = self.recv(size)
        return self.ctx2.ciphering(buffer)
