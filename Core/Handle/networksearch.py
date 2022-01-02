# -*- coding: utf-8 -*-
# @File  : networksearch.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.External.fofaclient import FOFAClient
from Lib.External.quake import Quake
from Lib.External.zoomeyeapi import ZoomeyeAPI
from Lib.api import data_return
from Lib.configs import NetworkSearch_MSG_ZH, CODE_MSG_ZH, CODE_MSG_EN, NetworkSearch_MSG_EN
from Lib.log import logger
from Lib.xcache import Xcache


class NetworkSearch(object):
    """网络测绘工具搜索(Quake,FOFA)"""

    def __init__(self):
        pass

    @staticmethod
    def list_search(engine, inputstr, page=1, size=100):
        if engine == "FOFA":
            # inputstr = inputstr.lower()
            # inputstr = inputstr.replace(" and ", " && ")
            # inputstr = inputstr.replace(" or ", " || ")
            # inputstr = inputstr.replace(":", "=")
            client = FOFAClient()
            flag = client.init_conf_from_cache()
        elif engine == "Quake":
            client = Quake()
            flag = client.init_conf_from_cache()
        elif engine == "Zoomeye":
            client = ZoomeyeAPI()
            flag = client.init_conf_from_cache()
        else:
            context = data_return(304, {}, NetworkSearch_MSG_ZH.get(304), NetworkSearch_MSG_EN.get(304))
            return context

        if flag is not True:
            context = data_return(301, {}, NetworkSearch_MSG_ZH.get(301), NetworkSearch_MSG_EN.get(301))
            return context
        try:
            flag, data = client.get_data(query_str=inputstr, page=page, size=size)
        except Exception as E:
            logger.exception(E)
            context = data_return(303, {"errmsg": NetworkSearch_MSG_EN.get(303)}, NetworkSearch_MSG_ZH.get(303),
                                  NetworkSearch_MSG_EN.get(303))
            return context

        if flag is not True:
            context = data_return(303, {"errmsg": data}, NetworkSearch_MSG_ZH.get(303),
                                  NetworkSearch_MSG_EN.get(303))
        else:
            context = data_return(200, data, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def list_engine():
        result = {"FOFA": False, "Quake": False, "Zoomeye": False, }
        fofaconf = Xcache.get_fofa_conf()
        result["FOFA"] = fofaconf.get("alive")

        quakeconf = Xcache.get_quake_conf()
        result["Quake"] = quakeconf.get("alive")

        zoomeyeconf = Xcache.get_zoomeye_conf()
        result["Zoomeye"] = zoomeyeconf.get("alive")

        context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context
