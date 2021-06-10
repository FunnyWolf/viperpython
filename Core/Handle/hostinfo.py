# -*- coding: utf-8 -*-
# @File  : hostinfo.py
# @Date  : 2021/6/10
# @Desc  :
from Lib.api import data_return
from Lib.configs import CODE_MSG
from Lib.xcache import Xcache


class HostInfo(object):

    @staticmethod
    def list(ipaddress):
        host_info = Xcache.get_host_info(ipaddress)
        context = data_return(200, CODE_MSG.get(200), host_info)
        return context
