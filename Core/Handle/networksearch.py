# -*- coding: utf-8 -*-
# @File  : networksearch.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.External.fofaclient import FOFAClient
from Lib.api import data_return
from Lib.configs import NetworkSearch_MSG, CODE_MSG
from Lib.log import logger


class NetworkSearch(object):
    """网络搜索引擎"""

    def __init__(self):
        pass

    @staticmethod
    def list(engine, querystr, page=1, size=100):
        if engine == "FOFA":
            client = FOFAClient()
            flag = client.init_conf_from_cache()
            if flag is not True:
                context = data_return(301, NetworkSearch_MSG.get(301), {})
                return context

        else:
            context = data_return(304, NetworkSearch_MSG.get(304), {})
            return context

        try:
            flag, data = client.get_data(query_str=querystr, page=page, size=size)
            if flag is not True:
                context = data_return(303, NetworkSearch_MSG.get(303), {"errmsg": data})
            else:
                context = data_return(200, CODE_MSG.get(200), data)
            return context

        except Exception as E:
            logger.exception(E)
            context = data_return(303, NetworkSearch_MSG.get(303), {"errmsg": NetworkSearch_MSG.get(303)})
            return context
