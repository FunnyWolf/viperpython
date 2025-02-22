# -*- coding: utf-8 -*-
# @File  : postmoduleauto.py
# @Date  : 2021/4/30
# @Desc  :
import json
import time
import uuid

from Lib.api import data_return
from Lib.configs import PostModuleAuto_MSG_ZH, CODE_MSG_ZH, CODE_MSG_EN, PostModuleAuto_MSG_EN
from Lib.configs import VIPER_POSTMODULE_AUTO_CHANNEL
from Lib.log import logger
from Lib.notice import Notice
from Lib.redisclient import RedisClient
from Lib.xcache import Xcache
from PostModule.Handle.postmoduleactuator import PostModuleActuator
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from PostModule.Handle.postmodulescheduler import PostModuleScheduler


class PostModuleAuto(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        # 自动编排任务信息
        auto_text_jobs = []
        postmodule_auto_dict = Xcache.get_postmodule_auto_dict()
        for module_uuid in postmodule_auto_dict:
            one_result = postmodule_auto_dict.get(module_uuid)
            one_result["_module_uuid"] = module_uuid
            loadpath = postmodule_auto_dict.get(module_uuid).get("loadpath")
            one_result["moduleinfo"] = Xcache.get_moduleconfig(loadpath)
            try:
                module_intent = PostModuleConfig.get_post_module_intent(loadpath=one_result["loadpath"],
                                                                        custom_param=json.loads(
                                                                            one_result["custom_param"]))
                one_result["opts"] = module_intent.get_readable_opts()
            except Exception as E:
                logger.exception(E)
                logger.warning(one_result)
                one_result["opts"] = {}

            auto_text_jobs.append(one_result)

        # 定时任务信息
        scheduler_text_jobs = PostModuleScheduler.list_jobs()
        context = data_return(200, {"auto": auto_text_jobs, "scheduler": scheduler_text_jobs}, CODE_MSG_ZH.get(200),
                              CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def create(loadpath, custom_param):
        module_uuid = str(uuid.uuid1())
        if Xcache.add_postmodule_auto_dict(module_uuid, loadpath, custom_param):
            context = data_return(201, {}, PostModuleAuto_MSG_ZH.get(201), PostModuleAuto_MSG_EN.get(201))
            return context
        else:
            context = data_return(306, {}, PostModuleAuto_MSG_ZH.get(306), PostModuleAuto_MSG_EN.get(306))
            return context

    @staticmethod
    def destory(module_uuid):
        if Xcache.delete_postmodule_auto_dict(module_uuid):
            context = data_return(204, {"_module_uuid": module_uuid}, PostModuleAuto_MSG_ZH.get(204),
                                  PostModuleAuto_MSG_EN.get(204))
            return context
        else:
            context = data_return(304, {}, PostModuleAuto_MSG_ZH.get(304), PostModuleAuto_MSG_EN.get(304))
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
            logger.exception(E)
            logger.warning(session_json)
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
            module_config = Xcache.get_moduleconfig(loadpath)
            Notice.send_info(f"执行自动化任务, 模块: {module_config.get('NAME_ZH')}",
                             f"Execute automation task, Module: {module_config.get('NAME_EN')}")

            context = PostModuleActuator.create_post(loadpath=loadpath,
                                                     sessionid=sessionid,
                                                     ipaddress=ipaddress,
                                                     custom_param=custom_param)
            if context.get('code') >= 300:  # 执行失败
                Notice.send_warning(f"自动编排执行失败,SID: {sessionid} MSG: {context.get('msg_zh')}",
                                    f"Failed to execute automation,SID: {sessionid} MSG: {context.get('msg_en')}")
        return
