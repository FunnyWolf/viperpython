# -*- coding: utf-8 -*-
# @File  : postmoduleresult.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, CODE_MSG_EN
from Lib.xcache import Xcache


class PostModuleResult(object):
    def __init__(self):
        pass

    @staticmethod
    def list(ipaddress=None, loadpath=None):
        result = Xcache.get_module_result(ipaddress=ipaddress, loadpath=loadpath)
        result_dict = {"ipaddress": ipaddress,
                       "loadpath": loadpath,
                       "update_time": result.get("update_time"),
                       "result": result.get("result")}

        context = data_return(200, result_dict, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context
