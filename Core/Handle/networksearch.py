# -*- coding: utf-8 -*-
# @File  : networksearch.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.External.fofaclient import FOFAClient
from Lib.External.quake import Quake
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
            inputstr = inputstr.lower()
            inputstr = inputstr.replace(" and ", " && ")
            inputstr = inputstr.replace(" or ", " || ")
            inputstr = inputstr.replace("=", ":")
            client = FOFAClient()
            flag = client.init_conf_from_cache()
        elif engine == "Quake":
            client = Quake()
            flag = client.init_conf_from_cache()
        elif engine == "Debug":
            data = NetworkSearch.get_debug_data()
            context = data_return(200, data, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context
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
    def get_debug_data():
        """生成debug数据"""
        data = [
            {
                "index": 0,
                "ip": "127.0.0.1",
                "port": 22,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "index": 1,
                "ip": "127.0.0.1",
                "port": 2222,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "index": 2,
                "ip": Xcache.get_lhost_config().get("lhost"),
                "port": 22,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "index": 3,
                "ip": Xcache.get_lhost_config().get("lhost"),
                "port": 80,
                "protocol": "http",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "index": 4,
                "ip": Xcache.get_lhost_config().get("lhost"),
                "port": 443,
                "protocol": "https",
                "country_name": "viper",
                "as_organization": "viper test",
            },
        ]

        for i in range(5, 100):
            data.append({
                "index": i,
                "ip": Xcache.get_lhost_config().get("lhost"),
                "port": 443,
                "protocol": "https",
                "country_name": "viper",
                "as_organization": "viper test",
            })

        return data

    @staticmethod
    def list_engine():
        result = {"FOFA": False, "Quake": False}
        fofaconf = Xcache.get_fofa_conf()
        result["FOFA"] = fofaconf.get("alive")
        quakeconf = Xcache.get_quake_conf()
        result["Quake"] = quakeconf.get("alive")
        context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context
