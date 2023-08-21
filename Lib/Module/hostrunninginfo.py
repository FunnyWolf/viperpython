# -*- coding: utf-8 -*-
# @File  : hostinfo.py
# @Date  : 2019/2/10
# @Desc  :

import json

from Lib.configs import RPC_SESSION_OPER_LONG_REQ
from Lib.log import logger
from Lib.msfmodule import MSFModule


class HostRunningInfo(object):
    """
    获取主机相关信息
    """

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
        result = MSFModule.run_msf_module_realtime(module_type=module_type, mname=mname, opts=opts,
                                                   timeout=RPC_SESSION_OPER_LONG_REQ)

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
            logger.warning(result)
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
