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
    """网络搜索引擎"""

    def __init__(self):
        pass

    @staticmethod
    def list_search(engine, moduleQuery, inputstr, page=1, size=100):
        if engine == "FOFA":
            if inputstr is None or inputstr.strip() == "":
                querystr = moduleQuery
            else:
                querystr = f"{moduleQuery} && {inputstr}"
            client = FOFAClient()
        elif engine == "Quake":
            if inputstr is None or inputstr.strip() == "":
                querystr = moduleQuery
            else:
                querystr = f"{moduleQuery} AND {inputstr}"
            client = Quake()
        else:
            context = data_return(304, {}, NetworkSearch_MSG_ZH.get(304), NetworkSearch_MSG_EN.get(304))
            return context

        flag = client.init_conf_from_cache()
        if flag is not True:
            context = data_return(301, {}, NetworkSearch_MSG_ZH.get(301), NetworkSearch_MSG_EN.get(301))
            return context

        try:
            flag, data = client.get_data(query_str=querystr, page=page, size=size)
            if flag is not True:
                context = data_return(303, {"errmsg": data}, NetworkSearch_MSG_ZH.get(303),
                                      NetworkSearch_MSG_EN.get(303))
            else:
                data.extend(NetworkSearch.get_test_data())
                context = data_return(200, data, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context

        except Exception as E:
            logger.exception(E)
            context = data_return(303, {"errmsg": NetworkSearch_MSG_ZH.get(303)}, NetworkSearch_MSG_EN.get(303))
            return context

    @staticmethod
    def get_test_data():
        """生成测试数据"""
        data = [
            {
                "ip": "127.0.0.1",
                "port": 2222,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "ip": "127.0.0.1",
                "port": 8888,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "ip": "192.168.146.130",
                "port": 2222,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
            {
                "ip": "192.168.146.130",
                "port": 8888,
                "protocol": "ssh",
                "country_name": "viper",
                "as_organization": "viper test",
            },
        ]
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
