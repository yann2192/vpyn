#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

import sys

class Progress:
    count = 0
    def __init__(self, msg, percentage=False):
        self.per = percentage
        self.msg = msg
        self.write()
        
    def add(self):
        self.count += 1
        self.write()

    def write(self):
        sys.stdout.write("\r%s : %d" % (self.msg,self.count))
        sys.stdout.flush()
