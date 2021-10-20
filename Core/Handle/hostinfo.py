# -*- coding: utf-8 -*-
# @File  : hostinfo.py
# @Date  : 2021/6/10
# @Desc  :
from Lib.xcache import Xcache


class HostInfo(object):

    @staticmethod
    def list(ipaddress):
        host_info = Xcache.get_host_info(ipaddress)
        return host_info
