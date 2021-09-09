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
            tmp_self_uuid = str(uuid.uuid1())

            # 清空历史记录
            post_module_intent._clean_log()

            logger.warning("模块放入列表:{} job_id: {} uuid: {}".format(post_module_intent.NAME, None, tmp_self_uuid))
            post_module_intent.module_self_uuid = tmp_self_uuid
            self.ModuleJobsScheduler.add_job(func=post_module_intent._thread_run, max_instances=1, id=tmp_self_uuid)

            # 放入缓存队列,用于后续删除任务,存储结果等
            req = {
                'broker': post_module_intent.MODULE_BROKER,
                'uuid': tmp_self_uuid,
                'module': post_module_intent,
                'time': int(time.time()),
                'job_id': None,
            }
            Xcache.create_module_task(req)
            # TODO
            Notice.send_info(
                "模块: {} {} 开始执行".format(post_module_intent.NAME, post_module_intent._target_str), "")
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
            logger.warning("缓存中无对应实例,可能已经模块已经中途退出")
            return False
        module_common_instance = req.get("module")

        # 存储运行结果
        try:
            module_common_instance._store_result_in_history()
            # TODO
            Notice.send_success(
                "模块: {} {} 执行完成".format(module_common_instance.NAME, module_common_instance._target_str), "")
            logger.warning("多模块实例执行完成:{}".format(module_common_instance.NAME))
            Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
            return True
        except Exception as E:
            Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
            logger.error("多模块实例执行异常:{} 异常信息: {}".format(module_common_instance.NAME, E))
            logger.error(E)
            return False

    @staticmethod
    def store_error_result(task_uuid=None, exception=None):
        req = Xcache.get_module_task_by_uuid(task_uuid=task_uuid)
        Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
        module_common_instance = req.get("module")

        # 存储运行结果
        try:
            module_common_instance.log_except(exception)
            module_common_instance._store_result_in_history()
            logger.error("多模块实例执行异常:{} 异常信息: {}".format(module_common_instance.NAME, exception))
            return True
        except Exception as E:
            logger.error("多模块实例执行异常:{} 异常信息: {}".format(module_common_instance.NAME, E))
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
            module_common_instance.log_info("用户手动删除任务")
            module_common_instance._store_result_in_history()
        except Exception as E:
            logger.error("删除多模块实例异常:{} 异常信息: {}".format(module_common_instance.NAME, E))
            logger.error(E)
            return False

        # 发送通知
        # TODO
        Notice.send_info(
            "模块: {} {} 手动删除".format(module_common_instance.NAME, module_common_instance._target_str), "")
        logger.warning("多模块实例手动删除:{}".format(module_common_instance.NAME))
        return True


aps_module = APSModule()
