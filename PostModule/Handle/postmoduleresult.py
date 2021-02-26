# -*- coding: utf-8 -*-
# @File  : postmoduleresult.py
# @Date  : 2021/2/26
# @Desc  :
from Core.Handle.host import Host
from Lib.api import data_return
from Lib.configs import CODE_MSG
from Lib.xcache import Xcache


class PostModuleResult(object):
    def __init__(self):
        pass

    @staticmethod
    def list(hid=None, loadpath=None):
        host = Host.get_by_hid(hid)
        result = Xcache.get_module_result(ipaddress=host.get("ipaddress"), loadpath=loadpath)
        result_dict = {"hid": hid,
                       "loadpath": loadpath,
                       "update_time": result.get("update_time"),
                       "result": result.get("result")}

        context = data_return(200, CODE_MSG.get(200), result_dict)
        return context
