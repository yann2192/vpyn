#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

import os, sys

home = os.getenv('USERPROFILE') or os.getenv('HOME')
home = '' # For test

inbox = os.path.join(home, 'inbox')
if os.path.exists(inbox) is False:
    os.mkdir(inbox)
elif os.path.isdir(inbox) is False:
    raise Exception, "%s already exist" % inbox

folder = os.path.join(home,'.VPyN')
if os.path.exists(folder) is False:
    os.mkdir(folder)
elif os.path.isdir(folder) is False:
    raise Exception, "%s already exist" % folder

indexfolder = os.path.join(folder, 'index')
if os.path.exists(indexfolder) is False:
    os.mkdir(indexfolder)
elif os.path.isdir(indexfolder) is False:
    raise Exception, "%s already exist" % indexfolder

database = os.path.join(folder, 'VPyN.db')
keyfile = os.path.join(folder, 'key.aes')
myindex = os.path.join(folder, 'index.db')
port = 8888
