# -*- coding: utf-8 -*-
# @File  : networktopology.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.api import data_return
from Lib.configs import CODE_MSG
from Lib.xcache import Xcache


class NetworkTopology(object):
    """网络图,废弃"""

    def __init__(self):
        pass

    @staticmethod
    def load_cache():
        cache_data = Xcache.get_network_topology_cache()
        if cache_data is None:
            cache_data = {}
        context = data_return(200, CODE_MSG.get(200), cache_data)
        return context

    @staticmethod
    def set_cache(cache_data):
        Xcache.set_network_topology_cache(cache_data)
        context = data_return(201, CODE_MSG.get(201), {})
        return context
