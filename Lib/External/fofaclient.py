# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :
import base64
import json
from urllib.parse import urlencode

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from Lib.xcache import Xcache


class FOFAClient:
    def __init__(self):
        self.email = None
        self.key = None
        self.base_url = "https://fofa.info"
        self.search_api_url = "/api/v1/search/all"
        self.login_api_url = "/api/v1/info/my"
        self.fields = ["ip", "port", "protocol", "country_name", "as_organization"]

    def set_email_and_key(self, email, key):
        self.email = email
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_fofa_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.email = conf.get("email")
            self.key = conf.get("key")
            return True

    def get_userinfo(self):
        api_full_url = "%s%s" % (self.base_url, self.login_api_url)
        param = {"email": self.email, "key": self.key}
        res = self.__http_get(api_full_url, param)
        return json.loads(res)

    def is_alive(self):
        # {"email":"XXX@XXX.org","username":"XXX","fcoin":0,"isvip":true,"vip_level":2,"is_verified":false,"avatar":"https://nosec.org/missing.jpg","message":0,"fofacli_ver":"3.10.4","fofa_server":true}
        userdata = self.get_userinfo()
        if userdata.get("email") == self.email:
            return True
        else:
            return False

    def get_data(self, query_str, page=1, size=100):
        res = self.get_json_data(query_str, page, size)
        data = json.loads(res)
        format_results = []
        if data.get("error") is False:
            results = data.get("results")
            i = 0
            for result in results:
                format_result = {"index": i}
                for field, value in zip(self.fields, result):
                    format_result[field] = value
                format_results.append(format_result)
                i += 1
            return True, format_results
        else:
            return False, data.get("errmsg")

    def get_json_data(self, query_str, page=1, size=100):
        api_full_url = "%s%s" % (self.base_url, self.search_api_url)
        param = {"qbase64": base64.b64encode(query_str.encode(encoding="UTF-8", errors="ignore")), "email": self.email,
                 "key": self.key,
                 "page": page,
                 "size": size,
                 "fields": ",".join(self.fields)}
        res = self.__http_get(api_full_url, param)
        return res

    @staticmethod
    def __http_get(url, param):
        param = urlencode(param)
        url = "%s?%s" % (url, param)

        try:
            r = requests.get(url=url, verify=False, headers={'Connection': 'close'})
            return r.text
        except Exception as e:
            raise e
