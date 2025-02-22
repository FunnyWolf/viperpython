#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''
# For keeping python2 support for now

import time

from Lib.api import parse_url_simple
from Lib.configs import WAFCHECK
from Lib.rpccall import RpcCall
from WebDatabase.Interface.dataset import DataSet
from WebDatabase.documents import WAFDocument


class WafCheck(object):

    @staticmethod
    def scan(urls, dataset: DataSet):
        rpc_response = RpcCall.rpc_call(worker=WAFCHECK, urls=urls)
        source = "wafw00f"
        for result in rpc_response:
            url = result.get("url")
            scheme, hostname, port = parse_url_simple(url)

            waf_obj = WAFDocument()

            waf_obj.source = source
            waf_obj.update_time = int(time.time())
            waf_obj.data = result

            waf_obj.ipdomain = hostname
            waf_obj.port = port

            waf_obj.trigger_url = result.get("trigger_url")
            waf_obj.name = result.get("firewall")
            waf_obj.manufacturer = result.get("manufacturer")

            detected = result.get("detected")
            if detected is None:
                continue
            else:
                waf_obj.flag = result.get("detected")
            dataset.wafList.append(waf_obj)
        return dataset
