# -*- coding: utf-8 -*-
# @File  : hostinfo.py
# @Date  : 2019/2/10
# @Desc  :

from Lib.xcache import Xcache


class HostInfo(object):
    """
    获取主机相关信息
    """

    def __init__(self):
        pass

    @staticmethod
    def get_info(ipaddress) -> dict:
        host_info = Xcache.get_host_info(ipaddress)
        return host_info

    @staticmethod
    def update_info(ipaddress, new_value: dict) -> dict:
        return Xcache.update_host_info(ipaddress, new_value)
