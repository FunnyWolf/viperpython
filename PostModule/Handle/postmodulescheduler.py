# -*- coding: utf-8 -*-
# @File  : postmoduleauto.py
# @Date  : 2021/4/30
# @Desc  :
import json
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
from PostModule.Handle.postmodulesingletonscheduler import postModuleSingletonScheduler


class PostModuleScheduler(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        result_list = []
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

            result_list.append(one_result)
        context = data_return(200, result_list, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def create(loadpath, custom_param, scheduler_session, scheduler_interval):
        job_uuid = str(uuid.uuid1())
        postModuleSingletonScheduler.add_job(func=PostModuleScheduler.handle_task,
                                             kwargs={
                                                 "loadpath": loadpath, "custom_param": custom_param,
                                                 "scheduler_session": scheduler_session,
                                             },
                                             max_instances=1,
                                             trigger='interval',
                                             seconds=scheduler_interval, id=job_uuid)

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
    def handle_task(loadpath, custom_param, scheduler_session):
        session_dict = Xcache.get_msf_sessions_by_id(scheduler_session)
        context = PostModuleActuator.create_post(loadpath=loadpath,
                                                 sessionid=scheduler_session,
                                                 ipaddress=session_dict.get("session_host"),
                                                 custom_param=custom_param)
        if context.get('code') >= 300:  # 执行失败
            Notice.send_warning(f"自动编排执行失败,SID: {scheduler_session} MSG: {context.get('msg_zh')}",
                                f"Failed to execute automation,SID: {scheduler_session} MSG: {context.get('msg_en')}")
        return
