# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
from Lib.xcache import Xcache


class WebSync(object):
    def __init__(self):
        pass

    @staticmethod
    def get_result():
        result = {
            'ipdomains_update': True,
            'ipdomains': None,
        }

        return result

    @staticmethod
    def first_result():
        cache_ipdomains_result = Xcache.get_websync_cache_ipdomains()
        result = {
            'ipdomains_update': True,
            'ipdomains': cache_ipdomains_result,
        }

        return result
