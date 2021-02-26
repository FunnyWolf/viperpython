# -*- coding: utf-8 -*-
# @File  : host.py
# @Date  : 2019/2/10
# @Desc  :

import json

from Core.Handle.host import Host as CoreHost
from Lib.log import logger
from Lib.msfmodule import MSFModule


class Host(object):
    def __init__(self, sessionid=None):
        self.sessionid = sessionid

    def _get_info(self, info_part):
        if self.sessionid is None:
            return None
        module_type = "post"
        mname = "multi/gather/base_info"
        opts = {'SESSION': self.sessionid, 'INFO_PART': info_part}
        if self.sessionid is None or self.sessionid <= 0:
            return None
        result = MSFModule.run(module_type=module_type, mname=mname, opts=opts)

        if result is None:
            return None
        try:
            result_dict = json.loads(result)
            if result_dict.get('status'):
                return result_dict.get('data')
            else:
                return None
        except Exception as E:
            logger.warning(E)
            return None

    @property
    def sysinfo(self):
        return self._get_info('SYSINFO')

    @property
    def processes(self):
        return self._get_info('PROCESSES')

    @property
    def netstat(self):
        return self._get_info('NETSTAT')

    @property
    def arp(self):
        return self._get_info('ARP')

    @property
    def interface(self):
        return self._get_info('INTERFACE')

    @staticmethod
    def add(ipaddress):
        """添加一个主机到数据库,返回hid"""
        result = CoreHost.create_host(ipaddress)
        hid = result.get('id')
        return hid

    @staticmethod
    def get_hid(ipaddress):
        """查找一个ipaddress的hid"""
        result = CoreHost.get_by_ipaddress(ipaddress)
        if result is not None:
            try:
                return result.get('id')
            except Exception as E:
                logger.error(E)
                return None
        else:
            return None

    @staticmethod
    def get_ipaddress(hid):
        """查找一个ipaddress的hid"""
        result = CoreHost.get_by_hid(hid)
        if result is not None:
            try:
                return result.get('ipaddress')
            except Exception as E:
                logger.error(E)
                return None
        else:
            return None

    @staticmethod
    def get_host(hid):
        """查找一个hid主机信息"""
        result = CoreHost.get_by_hid(hid)
        return result
