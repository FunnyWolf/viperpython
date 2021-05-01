# -*- coding: utf-8 -*-
# @File  : postmoduleauto.py
# @Date  : 2021/4/30
# @Desc  :
import json
import time
import uuid

from Lib.api import data_return
from Lib.configs import PostModuleAuto_MSG, CODE_MSG
from Lib.configs import VIPER_POSTMODULE_AUTO_CHANNEL
from Lib.log import logger
from Lib.notice import Notice
from Lib.redisclient import RedisClient
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostModule.Handle.postmoduleactuator import PostModuleActuator


class PostModuleAuto(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        result_list = []
        postmodule_auto_dict = Xcache.get_postmodule_auto_dict()
        for module_uuid in postmodule_auto_dict:
            one_result = postmodule_auto_dict.get(module_uuid)
            one_result["module_uuid"] = module_uuid
            loadpath = postmodule_auto_dict.get(module_uuid).get("loadpath")
            one_result["moduleinfo"] = Xcache.get_moduleconfig(loadpath)

            try:
                one_result["custom_param"] = Job._deal_dynamic_param(json.loads(one_result.get("custom_param")))
            except Exception as E:
                logger.warning(E)
                one_result["custom_param"] = {}
            result_list.append(one_result)
        context = data_return(200, CODE_MSG.get(200), result_list)
        return context

    @staticmethod
    def create(loadpath, custom_param):
        module_uuid = str(uuid.uuid1())
        if Xcache.add_postmodule_auto_list(module_uuid, loadpath, custom_param):
            context = data_return(201, PostModuleAuto_MSG.get(201), {})
            return context
        else:
            context = data_return(306, PostModuleAuto_MSG.get(306), {})
            return context

    @staticmethod
    def destory(module_uuid):
        if Xcache.delete_postmodule_auto_list(module_uuid):
            context = data_return(204, PostModuleAuto_MSG.get(204), {"module_uuid": module_uuid})
            return context
        else:
            context = data_return(304, PostModuleAuto_MSG.get(304), {})
            return context

    @staticmethod
    def send_task(session_json):
        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        result = rcon.publish(VIPER_POSTMODULE_AUTO_CHANNEL, session_json)

    @staticmethod
    def handle_task(message):
        session_json = message.get('data')
        # 解析报文
        try:
            session = json.loads(session_json)
        except Exception as E:
            logger.error(E)
            return False

        # 获取session配置
        sessionid = session.get("id")
        ipaddress = session.get("session_host")
        # 获取配置
        postmodule_auto_conf = Xcache.get_postmodule_auto_conf()
        interval = postmodule_auto_conf.get("interval")
        # 获取自动化列表
        postmodule_auto_dict = Xcache.get_postmodule_auto_dict()
        for module_uuid in postmodule_auto_dict:
            time.sleep(interval)
            loadpath = postmodule_auto_dict[module_uuid].get("loadpath")
            custom_param = postmodule_auto_dict[module_uuid].get("custom_param")
            context = PostModuleActuator.create_post(loadpath=loadpath,
                                                     sessionid=sessionid,
                                                     ipaddress=ipaddress,
                                                     custom_param=custom_param)
            if context.get('code') >= 300:  # 执行失败
                Notice.send_warning(f"自动编排执行失败,SID: {sessionid} MSG: {context.get('message')}")
        return
