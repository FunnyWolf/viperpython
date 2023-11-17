# -*- coding: utf-8 -*-
# @File  : apsmodule.py
# @Date  : 2021/2/26
# @Desc  :
import time
import uuid

from Lib.log import logger
from Lib.notice import Notice
from Lib.webmoduletask import WebModuleTask
from Lib.xcache import Xcache


class APSWebModule(object):
    """处理web python模块请求
    """

    def __init__(self):
        pass

    @staticmethod
    def putin_web_python_module_queue(web_module_intent=None):
        try:
            # 存储uuid
            module_uuid = str(uuid.uuid1())

            web_module_intent._module_uuid = module_uuid

            logger.warning(f"Web模块放入列表:{web_module_intent.NAME_ZH} uuid: {module_uuid}")

            # 放入缓存队列,用于后续删除任务,存储结果等
            task = WebModuleTask()
            task.broker = web_module_intent.MODULE_BROKER
            task.task_uuid = module_uuid
            task.module = web_module_intent
            task.time = int(time.time())

            Xcache.add_web_module_task(task)
            Notice.send_info(f"Web模块: {web_module_intent.NAME_ZH} {web_module_intent.target_str} 后台运行中",
                             f"Web Module: <{web_module_intent.NAME_EN}> {web_module_intent.target_str} running")
            return True
        except Exception as E:
            logger.error(E)
            return False

    @staticmethod
    def delete_job_by_uuid(task_uuid=None):
        task: WebModuleTask = Xcache.get_web_module_task(task_uuid=task_uuid)

        web_module_instance = task.module

        # 发送通知
        Notice.send_info(f"Web模块: {web_module_instance.NAME_ZH} {web_module_instance.target_str} 手动删除",
                         f"Web Module:<{web_module_instance.NAME_EN}> {web_module_instance.target_str} manually delete")
        logger.warning(f"多模块实例手动删除:{web_module_instance.NAME_ZH}")

        Xcache.del_web_module_task(task_uuid=task_uuid)  # 清理缓存信息
        return True

    @staticmethod
    def run_web_module_thread():
        task = Xcache.pop_web_module_task_from_waiting()
        if task is None:
            return
        web_module_instance = task.module
        try:
            module_result = web_module_instance._thread_run()
            Notice.send_info(f"Web 模块: {web_module_instance.NAME_ZH} {web_module_instance.target_str} 执行完成",
                             f"Web Module: <{web_module_instance.NAME_EN}> {web_module_instance.target_str} start running")
            logger.warning(f"多模块实例执行完成:{web_module_instance.NAME_ZH}")
            Xcache.del_web_module_task(task_uuid=task.task_uuid)  # 清理缓存信息
            return True

        except Exception as E:
            Xcache.del_web_module_task(task_uuid=task.task_uuid)  # 清理缓存信息
            logger.error(f"多模块实例执行异常:{web_module_instance.NAME_ZH} 异常信息: {E}")
            logger.error(E)
            return False
