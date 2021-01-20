# -*- coding: utf-8 -*-
# @File  : Host.py
# @Date  : 2019/2/10
# @Desc  :

import json

from Core.core import logger, Host as CoreHost
from Msgrpc.msgrpc import MSFModule
from PostLateral.postlateral import PortService


class Host(object):
    def __init__(self, sessionid=None):
        self.sessionid = sessionid

    def _get_info(self, info_part):
        if self.sessionid is None:
            return None
        type = "post"
        mname = "multi/gather/base_info"
        opts = {'SESSION': self.sessionid, 'INFO_PART': info_part}
        if self.sessionid is None or self.sessionid <= 0:
            return None
        result = MSFModule.run(type=type, mname=mname, opts=opts)

        if result is None:
            return None
        try:
            result_dict = json.loads(result)
            if result_dict.get('status') == True:
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

    @staticmethod
    def add_port_service(hid, port, proxy=None, banner=None, service=""):
        if proxy is None:
            proxy = {}
        if banner is None:
            banner = {}

        # 数据类型检查
        if isinstance(proxy, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(proxy))
            proxy = {}
        if isinstance(banner, dict) is not True:
            logger.warning('数据类型检查错误,数据 {}'.format(banner))
            banner = {}
        result = PortService.add_or_update(hid=hid, port=port, proxy=proxy, banner=banner, service=service)
        return result
