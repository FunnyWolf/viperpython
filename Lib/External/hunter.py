# -*- coding: utf-8 -*-
# @File  : fofaclient.py
# @Date  : 2021/2/25
# @Desc  :

import base64
import datetime
import time

import requests
import urllib3

from Lib.xcache import Xcache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Hunter(object):
    def __init__(self):
        self.key = None
        self.base_url = "https://hunter.qianxin.com"
        self.search_api_url = "/openApi/search"

    def set_key(self, key):
        self.key = key

    def init_conf_from_cache(self):
        conf = Xcache.get_hunter_conf()
        if conf.get("alive") is not True:
            return False
        else:
            self.key = conf.get("key")
            return True

    def check_alive(self):
        res = self.get_data('ip="10.10.10.10"', page=1, page_size=1)
        if res.get("code") == 200:
            return True
        else:
            return False

    def get_json_data(self, query_str, size=1000):
        if Xcache.get_sample_data("HUNTER_DOMAIN", query_str) is None:
            msg, res = self.get_all_data(query_str, size)
            Xcache.set_sample_data("HUNTER_DOMAIN", query_str, res)
        else:
            res = Xcache.get_sample_data("HUNTER_DOMAIN", query_str)
            msg = "success"
        # msg, res = self.get_all_data(query_str, size)
        return msg, res

    def get_all_data(self, query_str, size=1000):
        result = []
        page = 1
        res = self.get_data(query_str, page, 100)
        if res.get("code") == 200:
            arr = res.get("data").get("arr")
            if arr is None:
                return res.get("message"), []

            # print(f'{res.get("data").get("consume_quota")} {res.get("data").get("rest_quota")}')
            total = res.get("data").get("total")
            result.extend(arr)
        else:
            return res.get("message"), None

        if total <= 100:
            return res.get("message"), result

        while True:
            page += 1
            res = self.get_data(query_str, page, 100)
            time.sleep(3)
            if res.get("code") == 200:
                arr = res.get("data").get("arr")
                if arr is None:
                    break
                result.extend(arr)

                if len(result) >= size:
                    break
                if len(result) >= total:
                    break
            elif res.get("code") == 429:
                time.sleep(5)
                page -= 1
                continue
            else:
                break
        return res.get("message"), result

    def get_data(self, query_str, page, page_size):
        today = datetime.date.today()
        year_ago = today.replace(year=today.year - 1)

        api_full_url = f"{self.base_url}{self.search_api_url}"

        query_str = base64.urlsafe_b64encode(query_str.encode("utf-8")).decode("utf-8")

        data = {
            'api-key': self.key,
            "search": query_str,
            "page": page,
            "page_size": page_size,
            "is_web": 3,
            "start_time": str(year_ago),
            "end_time": str(today)
        }

        res = self.__http_get(api_full_url, data)
        return res

    def __http_get(self, url, params):
        try:
            headers = {
                "Content-Type": "application/json",
                'Connection': 'close'
            }
            r = requests.get(url=url, params=params, verify=False, headers=headers)
            return r.json()
        except Exception as e:
            return None
