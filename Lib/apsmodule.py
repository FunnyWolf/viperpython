# -*- coding: utf-8 -*-
# @File  : apsmodule.py
# @Date  : 2021/2/26
# @Desc  :
import threading
import time
import uuid

from apscheduler.events import EVENT_JOB_ADDED, EVENT_JOB_REMOVED, EVENT_JOB_MODIFIED, EVENT_JOB_EXECUTED, \
    EVENT_JOB_ERROR, EVENT_JOB_MISSED, EVENT_JOB_SUBMITTED, EVENT_JOB_MAX_INSTANCES
from apscheduler.schedulers.background import BackgroundScheduler

from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache


class APSModule(object):
    """处理post python模块请求,单例模式运行
    EVENT_JOB_ADDED | EVENT_JOB_REMOVED | EVENT_JOB_MODIFIED |EVENT_JOB_EXECUTED |
    EVENT_JOB_ERROR | EVENT_JOB_MISSED |EVENT_JOB_SUBMITTED | EVENT_JOB_MAX_INSTANCES
    """
    _instance_lock = threading.Lock()

    def __init__(self):

        self.ModuleJobsScheduler = BackgroundScheduler()
        self.ModuleJobsScheduler.add_listener(self.deal_result)
        self.ModuleJobsScheduler.start()

    def __new__(cls, *args, **kwargs):
        if not hasattr(APSModule, "_instance"):
            with APSModule._instance_lock:
                if not hasattr(APSModule, "_instance"):
                    APSModule._instance = object.__new__(cls)
        return APSModule._instance

    def putin_post_python_module_queue(self, post_module_intent=None):
        try:
            # 存储uuid
            module_uuid = str(uuid.uuid1())

            # 清空历史记录
            post_module_intent.clean_log()
            post_module_intent._module_uuid = module_uuid

            logger.warning(f"模块放入列表:{post_module_intent.NAME_ZH} uuid: {module_uuid}")
            self.ModuleJobsScheduler.add_job(func=post_module_intent._thread_run, max_instances=1, id=module_uuid)

            # 放入缓存队列,用于后续删除任务,存储结果等
            req = {
                'broker': post_module_intent.MODULE_BROKER,
                'uuid': module_uuid,
                'module': post_module_intent,
                'time': int(time.time()),
                'job_id': None,
            }
            Xcache.create_module_task(req)
            Notice.send_info(f"模块: {post_module_intent.NAME_ZH} {post_module_intent.target_str} 后台运行中",
                             f"Module: <{post_module_intent.NAME_EN}> {post_module_intent.target_str} running")
            return True
        except Exception as E:
            logger.error(E)
            return False

    def deal_result(self, event=None):
        flag = False
        if event.code == EVENT_JOB_ADDED:
            # print("EVENT_JOB_ADDED")
            pass
        elif event.code == EVENT_JOB_REMOVED:
            # print("EVENT_JOB_REMOVED")
            pass
        elif event.code == EVENT_JOB_MODIFIED:
            # print("EVENT_JOB_MODIFIED")
            pass
        elif event.code == EVENT_JOB_EXECUTED:  # 执行完成
            flag = self.store_executed_result(event.job_id)
        elif event.code == EVENT_JOB_ERROR:
            # print("EVENT_JOB_ERROR")
            flag = self.store_error_result(event.job_id, event.exception)
        elif event.code == EVENT_JOB_MISSED:
            # print("EVENT_JOB_MISSED")
            pass
        elif event.code == EVENT_JOB_SUBMITTED:
            # print("EVENT_JOB_SUBMITTED")
            pass
        elif event.code == EVENT_JOB_MAX_INSTANCES:
            # print("EVENT_JOB_MAX_INSTANCES")
            pass
        else:
            pass
        return flag

    @staticmethod
    def store_executed_result(task_uuid=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=task_uuid)
        if req is None:
            logger.warning("缓存中无对应实例,模块已中途退出")
            return False
        module_common_instance = req.get("module")

        # 存储运行结果
        try:
            module_common_instance.store_result_in_history()
            Notice.send_info(f"模块: {module_common_instance.NAME_ZH} {module_common_instance.target_str} 执行完成",
                             f"Module: <{module_common_instance.NAME_EN}> {module_common_instance.target_str} start running")
            logger.warning(f"多模块实例执行完成:{module_common_instance.NAME_ZH}")
            Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
            return True
        except Exception as E:
            Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
            logger.error(f"多模块实例执行异常:{module_common_instance.NAME_ZH} 异常信息: {E}")
            logger.error(E)
            return False

    @staticmethod
    def store_error_result(task_uuid=None, exception=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=task_uuid)
        Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
        module_common_instance = req.get("module")

        # 存储运行结果
        try:
            module_common_instance.log_except(str(exception), str(exception))
            module_common_instance.store_result_in_history()
            logger.error(f"多模块实例执行异常:{module_common_instance.NAME_ZH} 异常信息: {exception}")
            return True
        except Exception as E:
            logger.error(f"多模块实例执行异常:{module_common_instance.NAME_ZH} 异常信息: {E}")
            logger.error(E)
            return False

    def delete_job_by_uuid(self, task_uuid=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=task_uuid)
        Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息

        # 删除后台任务
        try:
            self.ModuleJobsScheduler.remove_job(task_uuid)
        except Exception as E:
            logger.error(E)

        try:
            module_common_instance = req.get("module")
        except Exception as E:
            logger.error(E)
            return False

        # 存储已经生成的结果
        try:
            module_common_instance.log_warning("用户手动删除任务", "User manually delete task")
            module_common_instance.store_result_in_history()
        except Exception as E:
            logger.error(f"删除多模块实例异常:{module_common_instance.NAME_ZH} 异常信息: {E}")
            logger.error(E)
            return False

        # 发送通知
        Notice.send_info(f"模块: {module_common_instance.NAME_ZH} {module_common_instance.target_str} 手动删除",
                         f"Module:<{module_common_instance.NAME_EN}> {module_common_instance.target_str} manually delete")
        logger.warning(f"多模块实例手动删除:{module_common_instance.NAME_ZH}")
        return True


aps_module = APSModule()
