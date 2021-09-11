# -*- coding: utf-8 -*-
# @File  : postmoduleresulthistory.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.api import data_return
from Lib.configs import PostModuleResultHistory_MSG
from Lib.log import logger
from Lib.xcache import Xcache


class PostModuleResultHistory(object):
    def __init__(self):
        pass

    @staticmethod
    def list_all():
        try:
            result = Xcache.list_module_result_history()
            for one in result:
                loadpath = one.get("loadpath")
                moduleconfig = Xcache.get_moduleconfig(loadpath)
                if moduleconfig is None:
                    continue
                # TODO

                one["NAME_EN"] = moduleconfig.get("NAME_EN")
                one["NAME_ZH"] = moduleconfig.get("NAME_ZH")
            return result
        except Exception as E:
            logger.exception(E)
            return []

    @staticmethod
    def destory():
        Xcache.del_module_result_history()
        context = data_return(204, {}, PostModuleResultHistory_MSG.get(204))
        return context
