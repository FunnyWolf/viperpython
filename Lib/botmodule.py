# -*- coding: utf-8 -*-
# @File  : botmodule.py
# @Date  : 2021/12/31
# @Desc  :

from Lib.Module.moduletemplate import BotPythonModule, BotMSFModule
from Lib.configs import RPC_RUN_MODULE_LONG
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient


class BotModule(object):
    """处理MSF模块执行请求,结果回调"""

    def __init__(self):
        pass

    @staticmethod
    def run_msf_module(msf_module: BotMSFModule):
        """实时运行bot_msf_job类型的任务"""

        params = [msf_module.type,
                  msf_module.mname,
                  msf_module.opts,
                  False,
                  msf_module.timeout  # 超时时间
                  ]

        result = RpcClient.call(Method.ModuleExecute, params, timeout=RPC_RUN_MODULE_LONG)
        if result is None:
            Notice.send_warning(f"渗透服务连接失败,无法执行模块 :{msf_module.NAME_ZH}",
                                f"MSFRPC connect failed and the module could not be executed :<{msf_module.NAME_EN}>")
            return False

        # 清理历史结果
        try:
            logger.warning(f"模块回调:{msf_module.NAME_ZH}")
            msf_module.clean_log()  # 清理历史结果
        except Exception as E:
            logger.error(E)
            return False

        # 调用回调函数
        flag = False
        try:
            flag = msf_module.callback(module_output=result)
        except Exception as E:
            Notice.send_exception(f"模块 {msf_module.NAME_ZH} 的回调函数callback运行异常",
                                  f"Module <{msf_module.NAME_EN}> callback running error")
            logger.error(E)

        # 如果是积极结果,存储
        if flag:
            try:
                msf_module.store_result_in_history()  # 存储到历史记录
            except Exception as E:
                logger.error(E)
            Notice.send_success(f"模块: {msf_module.NAME_ZH} {msf_module.target_str} 执行成功",
                                f"Module: <{msf_module.NAME_EN}> {msf_module.target_str} run success")
        else:
            Notice.send_info(f"模块: {msf_module.NAME_ZH} {msf_module.target_str} 执行完成",
                             f"Module: <{msf_module.NAME_EN}> {msf_module.target_str} run finish")

    @staticmethod
    def run_python_module(python_module: BotPythonModule):
        """实时运行bot_python_job类型的任务"""

        # 清理历史结果
        try:
            logger.warning(f"模块执行:{python_module.NAME_ZH}")
            python_module.clean_log()  # 清理历史结果
        except Exception as E:
            logger.error(E)
            return False

        # 调用回调函数
        flag = False
        try:
            flag = python_module.run()
        except Exception as E:
            Notice.send_exception(f"模块 {python_module.NAME_ZH} 的回调函数run运行异常",
                                  f"Module <{python_module.NAME_EN}> run func error")
            logger.error(E)

        # 如果是积极结果,存储
        if flag:
            try:
                python_module.store_result_in_history()  # 存储到历史记录
            except Exception as E:
                logger.error(E)
            Notice.send_success(f"模块: {python_module.NAME_ZH} {python_module.target_str} 执行成功",
                                f"Module: <{python_module.NAME_EN}> {python_module.target_str} run success")
        else:
            Notice.send_info(f"模块: {python_module.NAME_ZH} {python_module.target_str} 执行完成",
                             f"Module: <{python_module.NAME_EN}> {python_module.target_str} run finish")
