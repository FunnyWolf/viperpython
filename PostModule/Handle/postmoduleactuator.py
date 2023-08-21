# -*- coding: utf-8 -*-
# @File  : postmoduleactuator.py
# @Date  : 2021/2/26
# @Desc  :
import importlib
import json
import time
import uuid

from Lib.Module.configs import BROKER
from Lib.api import data_return, get_one_uuid_str
from Lib.apsmodule import aps_module
from Lib.configs import PostModuleActuator_MSG_ZH, PostModuleActuator_MSG_EN
from Lib.log import logger
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.xcache import Xcache


class PostModuleActuator(object):
    """任务添加器"""

    def __init__(self):
        pass

    @staticmethod
    def create_post(loadpath=None, sessionid=None, ipaddress=None, custom_param=None):
        module_config = Xcache.get_moduleconfig(loadpath)
        # 获取模块配置
        if module_config is None:
            context = data_return(305, {}, PostModuleActuator_MSG_ZH.get(305), PostModuleActuator_MSG_EN.get(305))
            return context

        # 处理模块参数
        if custom_param is None:
            custom_param = {}
        else:
            try:
                custom_param = json.loads(custom_param)
            except Exception as E:
                logger.exception(E)
                logger.warning(custom_param)
                custom_param = {}

        # 获取模块实例
        try:
            class_intent = importlib.import_module(loadpath)
            post_module_intent = class_intent.PostModule(sessionid, ipaddress, custom_param)
        except Exception as E:
            logger.warning(E)
            context = data_return(305, {}, PostModuleActuator_MSG_ZH.get(305), PostModuleActuator_MSG_EN.get(305))
            return context

        # 格式化固定字段
        # AUTHOR字段可能为list或者str,需要统一处理
        try:
            post_module_intent.AUTHOR = module_config.get("AUTHOR")
        except Exception as E:
            logger.warning(E)

        # 模块前序检查,调用check函数
        try:
            check_result = post_module_intent.check()
            # 模块忘记返回True,按照通过处理
            if check_result is None:
                pass
            else:
                if len(check_result) == 1:
                    flag = check_result
                    msg_zh = msg_en = ""
                elif len(check_result) == 2:
                    flag, msg_zh = check_result
                    msg_en = msg_zh
                elif len(check_result) == 3:
                    flag, msg_zh, msg_en = check_result
                else:
                    logger.warning(f"模块返回检查结果格式错误,check_result:{check_result}")
                    context = data_return(307, {}, PostModuleActuator_MSG_ZH.get(307),
                                          PostModuleActuator_MSG_EN.get(307))
                    return context
                if flag is not True:
                    # 如果检查未通过,返回未通过原因(msg)
                    context = data_return(405, {}, msg_zh, msg_en)
                    return context

        except Exception as E:
            logger.warning(E)
            context = data_return(301, {}, PostModuleActuator_MSG_ZH.get(301), PostModuleActuator_MSG_EN.get(301))
            return context

        try:
            broker = post_module_intent.MODULE_BROKER
        except Exception as E:
            logger.warning(E)
            context = data_return(305, {}, PostModuleActuator_MSG_ZH.get(305), PostModuleActuator_MSG_EN.get(305))
            return context

        if broker == BROKER.post_python_job:
            # 放入多模块队列
            if aps_module.putin_post_python_module_queue(post_module_intent):
                context = data_return(201, {}, PostModuleActuator_MSG_ZH.get(201), PostModuleActuator_MSG_EN.get(201))
                return context
            else:
                context = data_return(306, {}, PostModuleActuator_MSG_ZH.get(306), PostModuleActuator_MSG_EN.get(306))
                return context
        elif broker == BROKER.post_msf_job:
            # 放入后台运行队列
            if MSFModule.putin_msf_module_job_queue(post_module_intent):
                context = data_return(201, {}, PostModuleActuator_MSG_ZH.get(201), PostModuleActuator_MSG_EN.get(201))
                return context
            else:
                context = data_return(306, {}, PostModuleActuator_MSG_ZH.get(306), PostModuleActuator_MSG_EN.get(306))
                return context
        else:
            logger.warning("错误的broker")

    @staticmethod
    def create_bot(ipportlist=None, custom_param=None, loadpath=None):
        module_config = Xcache.get_moduleconfig(loadpath)
        # 获取模块配置
        if module_config is None:
            context = data_return(305, {}, PostModuleActuator_MSG_ZH.get(305), PostModuleActuator_MSG_EN.get(305))
            return context

        # 处理模块参数
        try:
            custom_param = json.loads(custom_param)
        except Exception as E:
            logger.exception(E)
            logger.warning(custom_param)
            custom_param = {}

        # 获取模块实例
        group_uuid = get_one_uuid_str()
        class_intent = importlib.import_module(loadpath)
        for ipport in ipportlist:
            post_module_intent = class_intent.PostModule(ip=ipport.get("ip"),
                                                         port=ipport.get("port"),
                                                         protocol=ipport.get("protocol"),
                                                         custom_param=custom_param)
            # 格式化固定字段
            # AUTHOR字段可能为list或者str,需要统一处理
            try:
                post_module_intent.AUTHOR = module_config.get("AUTHOR")
            except Exception as E:
                logger.warning(E)

            # 模块前序检查,调用check函数
            try:
                check_result = post_module_intent.check()
                # 模块忘记返回True,按照通过处理
                if check_result is None:
                    pass
                else:
                    flag = False
                    if len(check_result) == 1:
                        flag = check_result
                        msg_zh = msg_en = ""
                    elif len(check_result) == 2:
                        flag, msg_zh = check_result
                        msg_en = msg_zh
                    elif len(check_result) == 3:
                        flag, msg_zh, msg_en = check_result

                    if flag is not True:
                        # 如果检查未通过,返回未通过原因(msg)
                        Notice.send_warning(
                            f"模块:{post_module_intent.NAME_ZH} IP:{ipport.get('ip')} 检查未通过,原因:{msg_zh}",
                            f"Module: <{post_module_intent.NAME_EN}> IP:{ipport.get('ip')} check failed, reason:{msg_en}")
                        continue
            except Exception as E:
                logger.warning(E)
                Notice.send_warning(f"模块:{post_module_intent.NAME_ZH} IP:{ipport.get('ip')} 检查函数执行异常",
                                    f"Module:{post_module_intent.NAME_ZH} IP:{ipport.get('ip')} check function run exception")
                continue

            req = {
                'uuid': str(uuid.uuid1()),
                'group_uuid': group_uuid,
                'broker': post_module_intent.MODULE_BROKER,
                'module': post_module_intent,
                'time': int(time.time()),
            }
            Xcache.putin_bot_wait(req)

        context = data_return(201, {}, PostModuleActuator_MSG_ZH.get(201), PostModuleActuator_MSG_EN.get(201))
        return context
