#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

import sys, os, fcntl
from getpass import getpass
from hashlib import sha256
from base64 import b64encode, b64decode
from gevent import monkey, Greenlet, GreenletExit, sleep
from Crypto import ECC_key
from Manage import Manage
from Server import Server
from Client import Client
from Index import *
from Config import *
from Progress import Progress

class shell():
    commands = {
        "help" : "for help :)",
        "exit" : "To exit ;)",
        "addpeer" : "...",
        "listpeers" : "...",
        "rmpeer" : "...",
        "addfolder" : "...",
        "listfolders" : "...",
        "listmyfiles" : "...",
        "rmfolder" : "...",
        "getindex" : "...",
        "listfile" : "...",
        "downloadfile": "...",
        }

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
                print "[!] No peers ..."
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
            num = int(self._input('Peer Num : '))
            self.vpn.rm_peer_by_num(num)
        except Exception as e:
            print "[Error]",e
        else:
            print "[+] Peer deleted ..."

    def addfolder(self):
        try:
            path = self._input('Absolute path : ')
            c = Progress("Files add")
            from time import time
            a = time()
            self.vpn.index.add_folder(path, c)
            print "\n",time()-a
            del time
        except Exception as e:
            print "\n[Error]",e
        else:
            print "\n[+] Folder added : %s" % os.path.abspath(path)

    def listfolders(self):
        try:
            res = self.vpn.index.get_index()
            if res == []:
                print "[!] Index empty ..."
            else:
                for i in res:
                    print "ID : %d" % i[0]
                    print "Path : %s" % i[1]
        except Exception as e:
            print "[Error]",e

    def listmyfiles(self):
        try:
            index = self.vpn.index.list_index()
            if index == []:
                print "[!] Index empty ..."
            else :
                for i in index:
                    sys.stdout.write("- %d : %s\n" % (i[0],i[3]))
                    sys.stdout.flush()
                    sleep(0.0001)
        except Exception as e:
            print e

    def rmfolder(self):
        try:
            id = int(self._input('Folder ID : '))
            if self.vpn.index.rm_folder_by_id(id) == 0:
                raise Exception, "Unknown folder"
        except Exception as e:
            print "[Error]",e
        else:
            print "[+] Folder deleted ..."

    def getindex(self):
        try:
            num = int(self._input('Peer Num : '))
            peer = self.vpn.get_peer_by_num(num)
            clt = Client(self.vpn)
            print "[+] Connecting to %s at %s:%d ... [Ctrl+c]" % (peer[1], peer[2], peer[3])
            clt.connect(peer[2], peer[3], (peer[4],peer[5]))
            print "[+] Connected"
            print "[+] Get Index ..."
            clt.get_index(peer[0])
            clt.close()
        except Exception as e:
            print "[Error]", e
        except KeyboardInterrupt:
            print "[!] Connection close"
        else:
            print "[+] Index downloaded"

    def listfile(self):
        try:
            num = int(self._input('Peer Num : '))
            id = self.vpn.get_peer_by_num(num)[0]
            tmp = Index(id).list_index()
            for i in tmp:
                sleep(0)
                sys.stdout.write("- %d : %s | size : %d bytes\n" % (i[0],i[1], i[2]))
                sys.stdout.flush()
                sleep(0.0001)
        except Exception as e:
            print "[Error]",e

    def downloadfile(self):
        try:
            num = int(self._input('Peer Num : '))
            peer = self.vpn.get_peer_by_num(num)
            idfile = int(self._input('File ID : '))
            name = Index(peer[0]).get_file_by_id(idfile)[1]
            clt = Client(self.vpn)
            print "[+] Connecting to %s at %s:%d ... [Ctrl+c]" % (peer[1], peer[2], peer[3])
            clt.connect(peer[2], peer[3], (peer[4],peer[5]))
            print "[+] Connected"
            print '[+] Get File "%s" ...' % name
            clt.get_file(idfile, name)
            clt.close()
        except Exception as e:
            print "[Error]", e
        except KeyboardInterrupt:
            print "[!] Connection close"
        else:
            print "[+] File downloaded"

def main():
    my = Manage(getpass('Enter password: '))
    my.index = MyIndex()
    print "ID : %s" % sha256(my.ecc.pubkey_x+my.ecc.pubkey_y).hexdigest()
    print "Public Key x : %s " % my.ecc.pubkey_x.encode('hex')
    print "Public Key y : %s" % my.ecc.pubkey_y.encode('hex')
    print "\ntry help for help ;)"
    # Now asynchrone 
    monkey.patch_all()
    fcntl.fcntl(sys.stdin, fcntl.F_SETFL, os.O_NONBLOCK)
    S = shell(my)
    server = Server(port, my)
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
