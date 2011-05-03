#!/usr/bin/env python
# -*- coding: utf-8 -*-
########################################################################
#  VPyN.py - (?)
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

import sys, os, fcntl
from getpass import getpass
from hashlib import sha256
from base64 import b64encode, b64decode
from gevent import monkey, Greenlet, GreenletExit, sleep
from Crypto import ECC_key
from Manage import Manage
from Server import Server
from Client import Client

if len(sys.argv) > 1: port = int(sys.argv[1])
else: port = 8000

class shell():
    commands = {
        "help" : "for help :)",
        "exit" : "To exit ;)",
        "addpeer" : "...",
        "listpeers" : "...",
        "rmpeer" : "...",
        "addfolder" : "...",
        "getindex" : "...",
        "listindex" : "...",
        "rmfolder" : "...",
        "connect" : "..."
        }

    def connect(self):
        try:
            num = int(self._input('Num : '))
            peer = self.vpn.get_peer_by_num(num)
            if peer == None:
                raise Exception, "Unknown peer ..."
            clt = Client(self.vpn)
            print "Connecting to %s at %s:%d ... [Ctrl+c]" % (peer[1], peer[2], peer[3])
            clt.connect(peer[2], peer[3], (peer[4],peer[5]))
            print "Connected"
            clt.ssend("test")
            while 1:
                sleep(0.1)
        except Exception as e:
            print e
        except KeyboardInterrupt:
            print "Connection close"

    def __init__(self, vpn):
        self.vpn = vpn

    def loop(self):
        while True:
            buffer = self._input('\n> ')
            if buffer == "exit":
                return
            elif buffer in self.commands:
                eval("self.%s()" % buffer)
            else:
                print "Command not found"

    def _input(self, msg):
        sys.stdout.write(msg)
        while True:
            try:
                sleep(0.1)
                return sys.stdin.readline().replace('\n','')
            except IOError:
                pass

    def help(self):
        for i in self.commands:
            print i,":",self.commands[i]

    def exit(self):
        pass

    def addpeer(self):
        try:
            nick = self._input('Nick : ')
            host = self._input('Host : ')
            port = int(self._input('Port : '))
            pubkey_x = self._input('Pubkey_x : ').decode('hex')
            pubkey_y = self._input('Pubkey_y : ').decode('hex')
            ECC_key(pubkey_x, pubkey_y)
            self.vpn.add_peer(nick, host, port, pubkey_x, pubkey_y)
        except Exception as e:
            print "[Error]",e
        else:
            print "[+] Peer added : %s" % sha256(pubkey_x+pubkey_y).hexdigest()        

    def listpeers(self):
        try:
            res = self.vpn.get_all_peers()
            if res == []:
                print "No peers ..."
            else:
                for i in res:
                    print "Num : %d" % i[0]
                    print "Nick : %s" % i[2]
                    print "Host : %s" % i[3]
                    print "Port : %d" % i[4]
                    print "ID : %s" % i[1].encode('hex')
                    print "Pubkey_x : %s" % i[5].encode('hex')
                    print "Pubkey_y : %s" % i[6].encode('hex')
        except Exception as e:
            print "[Error]",e

    def rmpeer(self):
        try:
            num = int(self._input('Num : '))
            self.vpn.rm_peer_by_num(num)
        except Exception as e:
            print "[Error]",e
        else:
            print "Peer deleted ..."

    def addfolder(self):
        try:
            path = os.path.abspath(self._input('Absolute path : '))
            self.vpn.add_folder(path)
        except Exception as e:
            print "[Error]",e
        else:
            print "[+] Folder added : %s" % path

    def getindex(self):
        try:
            res = self.vpn.get_index()
            if res == []:
                print "Index empty ..."
            else:
                for i in res:
                    print "Num : %d" % i[0]
                    print "Path : %s" % i[1]
        except Exception as e:
            print "[Error]",e

    def listindex(self):
        try:
            index = self.vpn.list_index()
            if index is []:
                print "Index empty ..."
            else :
                for i in index:
                    print "- %s" % i
                    sleep(0.00001)
        except Exception as e:
            print e

    def rmfolder(self):
        try:
            num = int(self._input('Num : '))
            self.vpn.rm_folder_by_num(num)
        except Exception as e:
            print "[Error]",e
        else:
            print "Folder deleted ..."

def main():
    my = Manage(getpass('Enter password: '))
    print "ID : %s" % sha256(my.ecc.pubkey_x+my.ecc.pubkey_y).hexdigest()
    print "Public Key x : %s " % my.ecc.pubkey_x.encode('hex')
    print "Public Key y : %s" % my.ecc.pubkey_y.encode('hex')
    print "\ntry help for help ;)"
    # Now asynchrone 
    monkey.patch_all()
    fcntl.fcntl(sys.stdin, fcntl.F_SETFL, os.O_NONBLOCK)
    S = shell(my)
    server = Server(8000, my)
    try:
        S.loop()
    except KeyboardInterrupt:
        pass
    if server.ready() is False:
        server.kill(block=True)
    print "Bye"
    sys.exit(0)

if __name__ == '__main__':
    main()
