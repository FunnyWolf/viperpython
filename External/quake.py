# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import requests
import urllib3

from Lib.xcache import Xcache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Quake(object):
    def __init__(self):
        self.key = None
        self.base_url = "https://quake.360.cn"
        self.search_api_url = "/api/v3/search/quake_service"
        # self.search_api_url = "/api/v3/scroll/quake_service"
        self.user_info_url = "/api/v3/user/info"
        self.fields = ["ip", "port", "protocol", "country_name", "as_organization"]
        self.headers = {
            "X-QuakeToken": self.key,
            "Content-Type": "application/json",
            'Connection': 'close'
        }

    def set_key(self, key):
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_quake_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def get_userinfo(self):
        api_full_url = f"{self.base_url}{self.user_info_url}"

        res = self.__http_get(api_full_url)
        return res

    def check_alive(self):
        userdata = self.get_userinfo()
        if userdata is None:
            return False
        if userdata.get("message") == "Successful.":
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        msg, data = self.get_json_data(query_str, page, size)
        if data:
            format_results = []
            i = 0
            for onedict in data:
                one_line = {
                    "index": i,
                    "ip": onedict.get('ip'),
                    "port": onedict.get('port'),
                    "protocol": onedict.get('service').get('name'),
                    "country_name": onedict.get('location').get('country_cn'),
                    "as_organization": onedict.get('location').get('isp'),
                }
                format_results.append(one_line)
                i += 1
            return True, format_results
        else:
            return False, msg

    def get_json_data(self, query_str, page=1, size=1000):
        api_full_url = f"{self.base_url}{self.search_api_url}"
        data = {
            "query": query_str,
            "start": (page - 1) * size,
            "size": size,
        }

        # debug hook start
        if Xcache.get_sample_data("QUAKE_DOMAIN", query_str) is None:
            res = self.__http_post(api_full_url, data)
            Xcache.set_sample_data("QUAKE_DOMAIN", query_str, res)
        else:
            res = Xcache.get_sample_data("QUAKE_DOMAIN", query_str)
        # debug hook end
        # res = self.__http_post(api_full_url, data)

        if res.get("message") == 'Successful.':
            # 处理meta部分,确保获取到所有数据
            return res.get("message"), res.get("data")
        else:
            return res.get("message"), None

    def __http_post(self, url, data):
        try:
            headers = {
                "X-QuakeToken": self.key,
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.post(url=url, json=data, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None

    def __http_get(self, url):
        try:
            headers = {
                "X-QuakeToken": self.key,
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.get(url=url, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None