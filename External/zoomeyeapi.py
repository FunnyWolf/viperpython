# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import requests
import urllib3

from Lib.xcache import Xcache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ZoomeyeAPI(object):
    def __init__(self):
        self.key = None
        self.base_url = "https://api.zoomeye.org"
        self.user_info_url = "/resources-info"
        self.search_api_url = "/host/search"
        self.headers = {
            "API-KEY": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }

    def set_key(self, key):
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_zoomeye_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def __http_get(self, url, params=None):
        try:
            headers = {
                "API-KEY": self.key,
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.get(url=url, params=params, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None

    def get_userinfo(self):
        api_full_url = f"{self.base_url}{self.user_info_url}"

        res = self.__http_get(api_full_url)
        return res

    def is_alive(self):
        userdata = self.get_userinfo()
        if userdata is None:
            return False
        if userdata.get("code") == 60000:
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        params = {'query': query_str, page: page}
        try:
            result = self.__http_get(api_full_url, params=params)
            code = result.get("code")
            total = result.get("total")
            available = result.get("available")
            matches = result.get("matches")
            facets = result.get("facets")

            format_results = []
            i = 0
            for onedict in matches:
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

    def get_json_data(self, query_str, page=1, size=1000):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        params = {'query': query_str, page: page}
        try:

            # debug hook start
            if Xcache.get_sample_data("ZOOMEYE_DOMAIN", query_str) is None:
                result = self.__http_get(api_full_url, params=params)
                Xcache.set_sample_data("ZOOMEYE_DOMAIN", query_str, result)
            else:
                result = Xcache.get_sample_data("ZOOMEYE_DOMAIN", query_str)
            # debug hook end

            # result = self.__http_get(api_full_url, params=params)
            code = result.get("code")
            total = result.get("total")
            available = result.get("available")
            matches = result.get("matches")
            facets = result.get("facets")
            return None, matches

        except Exception as E:
            return str(E), None
