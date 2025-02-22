# -*- coding: utf-8 -*-
# @File  : lazyloader.py
# @Date  : 2021/2/25
# @Desc  :
import time

from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, LazyLoader_MSG_ZH, CODE_MSG_EN, LazyLoader_MSG_EN
from Lib.xcache import Xcache


class CollectSandBox(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        data = Xcache.list_checksandbox()
        context = data_return(200, data, CODE_MSG_ZH.get(200),
                              CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def list_tag():
        data = Xcache.get_checksandbox_tag()
        context = data_return(200, {"tag": data}, CODE_MSG_ZH.get(200),
                              CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def update(tag):
        Xcache.update_checksandbox_tag(tag)
        context = data_return(201, {"tag": tag}, LazyLoader_MSG_ZH.get(201), LazyLoader_MSG_EN.get(201))
        return context

    @staticmethod
    def destory(ipaddress):
        data = Xcache.del_checksandbox(ipaddress)
        context = data_return(202, data, LazyLoader_MSG_ZH.get(202), LazyLoader_MSG_EN.get(202))
        return context

    @staticmethod
    def list_interface(query_params, ipaddress):
        """loader 对外接口"""
        tag = Xcache.get_checksandbox_tag()
        loader_uuid = query_params.get(tag, None)
        if len(loader_uuid) != 16:  # 检查uuid
            context = f""
            return context
        else:
            Xcache.add_to_checksandbox(ipaddress, int(time.time()))
            context = f""
            return context
