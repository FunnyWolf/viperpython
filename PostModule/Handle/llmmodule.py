# -*- coding: utf-8 -*-
# @File  : postmoduleactuator.py
# @Date  : 2021/2/26
# @Desc  :
import importlib

from Lib.Module.moduletemplate import LLMPythonModule
from Lib.api import data_return
from Lib.configs import PostModuleActuator_MSG_ZH, PostModuleActuator_MSG_EN, LLMModule_MSG_ZH, LLMModule_MSG_EN
from Lib.log import logger
from Lib.xcache import Xcache


class LLMModule(object):
    """任务添加器"""

    def __init__(self):
        pass

    # @staticmethod
    # def list(load_path=None):
    #     messages_dict = []
    #     message_history = llmapi.get_session_history(load_path=load_path)
    #     messages = message_history.messages
    #     for message in messages:
    #         messages_dict.append(message_to_dict(message))
    #     return messages_dict

    # @staticmethod
    # def list(load_path=None):
    #     # 需要实际加载模块,然后调用模块的list函数
    #     config = {"configurable": {"thread_id": load_path}}
    #
    #     workflow = StateGraph(MessagesState)
    #     conn = RedisClient.get_langgraph_contection()
    #     checkpointer = RedisSaver(conn)
    #
    #     graph: CompiledStateGraph = workflow.compile(checkpointer=checkpointer)
    #     graph_state: StateSnapshot = graph.get_state(config)
    #     values = graph_state.values
    #     messages = values.get("messages")
    #     messages_dict = []
    #     for message in messages:
    #         messages_dict.append(message_to_dict(message))
    #
    #     return messages_dict
    @staticmethod
    def list(load_path=None):
        # 获取模块实例
        try:
            class_intent = importlib.import_module(load_path)
            module_object: LLMPythonModule = class_intent.PostModule({})
        except Exception as E:
            logger.exception(E)
            return []
        messages_dict = module_object.list()
        return messages_dict

    @staticmethod
    def create(load_path=None, message=None):
        module_config = Xcache.get_moduleconfig(load_path)
        # 获取模块配置
        if module_config is None:
            context = data_return(305, {}, PostModuleActuator_MSG_ZH.get(305), PostModuleActuator_MSG_EN.get(305))
            return context

        # 处理模块参数
        if message is None:
            message = {}

        # 获取模块实例
        try:
            class_intent = importlib.import_module(load_path)
            module_object: LLMPythonModule = class_intent.PostModule(message)
        except Exception as E:
            logger.exception(E)
            context = data_return(308, {}, PostModuleActuator_MSG_ZH.get(308), PostModuleActuator_MSG_EN.get(308))
            return context

        # 模块前序检查,调用check函数
        try:
            check_result = module_object.check()
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
            logger.info("开始执行模块:{}".format(load_path))
            module_object.run()
            logger.info("模块执行完成:{}".format(load_path))
        except Exception as E:
            logger.exception(E)
            context = data_return(305, {}, str(E), str(E))
            return context

    @staticmethod
    def destroy(load_path=None):
        # 获取模块实例
        try:
            class_intent = importlib.import_module(load_path)
            module_object: LLMPythonModule = class_intent.PostModule({})
        except Exception as E:
            logger.exception(E)
            return []
        flag = module_object.delete()
        context = data_return(204, flag, LLMModule_MSG_ZH.get(204), LLMModule_MSG_EN.get(204))
        return context
