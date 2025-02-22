# -*- coding: utf-8 -*-
# @File  : apsmodule.py
# @Date  : 2021/2/26
# @Desc  :
import time
import uuid

from Lib.log import logger
from Lib.notice import Notice
from Lib.webmoduletask import WebModuleTask, WebModuleTaskStatus
from Lib.webnotice import WebNotice
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

            logger.info(f"Web模块放入列表:{web_module_intent.NAME_ZH} uuid: {module_uuid}")

            # 放入缓存队列,用于后续删除任务
            task = WebModuleTask()
            task.broker = web_module_intent.MODULE_BROKER
            task.task_uuid = module_uuid
            task.module = web_module_intent
            task.opts = web_module_intent.get_readable_opts()

            task.time = int(time.time())

            # 加入到任务队列
            add_task_flag = Xcache.add_web_module_task(task)

            # 更新结果状态
            update_task_result_flag = Xcache.add_web_module_result(
                task_uuid=task.task_uuid,
                loadpath=web_module_intent.__module__,
                opts=web_module_intent.get_readable_opts(),
                input_list=web_module_intent.input_list,
                project_id=web_module_intent.project_id,
                web_module_intent=web_module_intent,
            )

            Notice.send_info(f"Web模块: {web_module_intent.NAME_ZH} {web_module_intent.target_str} 后台运行中",
                             f"Web Module: <{web_module_intent.NAME_EN}> {web_module_intent.target_str} running")
            return True
        except Exception as E:
            logger.exception(E)
            return False

    @staticmethod
    def delete_job_by_uuid(task_uuid=None):
        task: WebModuleTask = Xcache.get_web_module_task(task_uuid=task_uuid)
        if task is None:
            logger.warning(f"Task not exist:{task_uuid}")
        else:
            web_module_instance = task.module

            # 发送通知
            Notice.send_info(f"Web模块: {web_module_instance.NAME_ZH} {web_module_instance.target_str} 手动删除",
                             f"Web Module:<{web_module_instance.NAME_EN}> {web_module_instance.target_str} manually delete")
            logger.info(f"多模块实例手动删除:{web_module_instance.NAME_ZH}")

        Xcache.update_web_module_result_status(task_uuid=task_uuid, status=WebModuleTaskStatus.cancel)
        Xcache.del_web_module_task(task_uuid=task_uuid)
        return True

    @staticmethod
    def run_web_module_thread() -> bool:
        task = Xcache.pop_web_module_task_from_waiting()
        if task is None:
            return False
        web_module_instance = task.module
        Xcache.update_web_module_result_status(task_uuid=task.task_uuid, status=WebModuleTaskStatus.running)
        try:  # only can catch exception come from t1.raise_exc
            web_module_instance.thread_run()
        except Exception as E:
            if str(E) == "the thread is not active":  # 特殊判断
                Xcache.update_web_module_result_status(task_uuid=task.task_uuid, status=WebModuleTaskStatus.cancel)
                Xcache.del_web_module_task(task_uuid=task.task_uuid)
                web_module_instance.log_except("任务已取消", "Task has been canceled")
                return True
            else:
                Xcache.update_web_module_result_status(task_uuid=task.task_uuid, status=WebModuleTaskStatus.error)
                Xcache.del_web_module_task(task_uuid=task.task_uuid)
                logger.error(f"多模块实例执行异常:{web_module_instance.NAME_ZH} 异常信息: {E}")
                logger.exception(E)
                web_module_instance.log_except(str(E))
                return False

        WebNotice.send_info(f"Web 模块: {web_module_instance.NAME_ZH} {web_module_instance.target_str} 执行完成",
                            f"Web Module: <{web_module_instance.NAME_EN}> {web_module_instance.target_str} finish")
        logger.info(f"多模块实例执行完成:{web_module_instance.NAME_ZH}")

        Xcache.update_web_module_result_status(task_uuid=task.task_uuid, status=web_module_instance.task_status)
        Xcache.del_web_module_task(task_uuid=task.task_uuid)
        return True
