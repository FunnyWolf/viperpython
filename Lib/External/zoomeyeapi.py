# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from zoomeye.sdk import ZoomEye

from Lib.xcache import Xcache


class ZoomeyeAPI:
    def __init__(self):
        self.key = None
        self.zm: ZoomEye = None

    def set_key(self, key):
        self.key = key
        self.zm = ZoomEye(api_key=self.key)

    def init_conf_from_cache(self):
        conf = Xcache.get_zoomeye_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            self.zm = ZoomEye(api_key=self.key)
            return True

    def is_alive(self):
        try:
            resources_info = self.zm.resources_info()
            return True
        except Exception as E:
            return False

    def get_data(self, query_str, page=1, size=100):
        result = self.zm.dork_search(query_str, page=page, )
        try:
            format_results = []
            i = 0
            for onedict in result:
                try:
                    ip = onedict.get("ip")
                    port = onedict.get("portinfo").get("port")
                    protocol = onedict.get("portinfo").get("service")
                    country_name = onedict.get("geoinfo").get("country").get("names").get("zh-CN")
                    as_organization = onedict.get("geoinfo").get("organization")
                    one_line = {
                        "index": i,
                        "ip": ip,
                        "port": port,
                        "protocol": protocol,
                        "country_name": country_name,
                        "as_organization": as_organization,
                    }
                except Exception as E:
                    continue
                format_results.append(one_line)
                i += 1
            return True, format_results
        except Exception as E:
            return False, str(E)
