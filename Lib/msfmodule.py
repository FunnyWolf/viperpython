# -*- coding: utf-8 -*-
# @File  : msfmodule.py
# @Date  : 2021/2/26
# @Desc  :
import json
import time

from Lib.configs import RPC_JOB_API_REQ, RPC_SESSION_OPER_SHORT_REQ, RPC_RUN_MODULE_LONG
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache


class MSFModule(object):
    """处理MSF模块执行请求,结果回调"""

    def __init__(self):
        pass

    @staticmethod
    def run(module_type=None, mname=None, opts=None, runasjob=False, timeout=RPC_SESSION_OPER_SHORT_REQ):
        """实时运行MSF模块"""
        params = [module_type,
                  mname,
                  opts,
                  runasjob,
                  timeout]
        result = RpcClient.call(Method.ModuleExecute, params, timeout=timeout)
        return result

    @staticmethod
    def putin_post_msf_module_queue(msf_module=None):
        """调用msgrpc生成job,放入列表"""

        params = [msf_module.type,
                  msf_module.mname,
                  msf_module.opts,
                  True,  # 强制设置后台运行
                  RPC_JOB_API_REQ  # 超时时间
                  ]

        result = RpcClient.call(Method.ModuleExecute, params, timeout=RPC_JOB_API_REQ)
        if result is None:
            Notice.send_warning(f"渗透服务连接失败,无法执行模块 :{msf_module.NAME}")
            return False

        # result 数据格式
        # {'job_id': 3, 'uuid': 'dbcb2530-95b1-0137-5100-000c2966078a', 'module': b'\x80\ub.'}

        if result.get("job_id") is None:
            logger.warning("模块实例:{} uuid: {} 创建后台任务失败".format(msf_module.NAME, result.get("uuid")))
            Notice.send_warning("模块: {} {} 创建后台任务失败,请检查输入参数".format(msf_module.NAME, msf_module._target_str))
            return False
        else:
            logger.warning(
                "模块实例放入列表:{} job_id: {} uuid: {}".format(msf_module.NAME, result.get("job_id"), result.get("uuid")))
            # 放入请求队列
            req = {
                'broker': msf_module.MODULE_BROKER,
                'uuid': result.get("uuid"),
                'module': msf_module,
                'time': int(time.time()),
                'job_id': result.get("job_id"),
            }
            Xcache.create_module_task(req)
            Notice.send_info("模块: {} {} 开始执行".format(msf_module.NAME, msf_module._target_str))
            return True

    @staticmethod
    def run_bot_msf_module(msf_module=None):
        """实时运行bot_msf_job类型的任务"""

        params = [msf_module.type,
                  msf_module.mname,
                  msf_module.opts,
                  False,
                  msf_module.timeout  # 超时时间
                  ]

        result = RpcClient.call(Method.ModuleExecute, params, timeout=RPC_RUN_MODULE_LONG)
        if result is None:
            Notice.send_warning(f"渗透服务连接失败,无法执行模块 :{msf_module.NAME}")
            return False

        # 清理历史结果
        try:
            logger.warning(f"模块回调:{msf_module.NAME}")
            msf_module._clean_log()  # 清理历史结果
        except Exception as E:
            logger.error(E)
            return False

        # 调用回调函数
        flag = False
        try:
            flag = msf_module.callback(module_output=result)
        except Exception as E:
            Notice.send_error("模块 {} 的回调函数callhack运行异常".format(msf_module.NAME))
            logger.error(E)

        # 如果是积极结果,存储
        if flag:
            try:
                msf_module._store_result_in_history()  # 存储到历史记录
            except Exception as E:
                logger.error(E)

        Notice.send_success("模块: {} {} 执行完成".format(msf_module.NAME, msf_module._target_str))

    @staticmethod
    def store_result_from_sub(message=None):
        # 回调报文数据格式
        # {
        # 'job_id': None,
        # 'uuid': '1b1a1ac0-95db-0137-5103-000c2966078a',
        # 'status': True,
        # 'message': None,
        # 'data': {'WHOAMI': 'nt authority\\system', 'IS_SYSTEM': True, }
        # }
        body = message.get('data')
        # 解析报文
        try:
            msf_module_return_dict = json.loads(body)
        except Exception as E:
            logger.error(E)
            return False

        # 获取对应模块实例
        try:
            req = Xcache.get_module_task_by_uuid(task_uuid=msf_module_return_dict.get("uuid"))
        except Exception as E:
            logger.error(E)
            return False

        if req is None:
            logger.error("未找到请求模块实例")
            logger.error(msf_module_return_dict)
            return False

        module_intent = req.get('module')
        if module_intent is None:
            logger.error("获取模块失败,body: {}".format(msf_module_return_dict))
            return False

        # 调用回调函数
        try:
            logger.warning(f"模块回调:{module_intent.NAME} "
                           f"job_id: {msf_module_return_dict.get('job_id')} "
                           f"uuid: {msf_module_return_dict.get('uuid')}")
            module_intent._clean_log()  # 清理历史结果
        except Exception as E:
            logger.error(E)
            return False

        try:
            module_intent.callback(status=msf_module_return_dict.get("status"),
                                   message=msf_module_return_dict.get("message"),
                                   data=msf_module_return_dict.get("data"))
        except Exception as E:
            Notice.send_error("模块 {} 的回调函数callhack运行异常".format(module_intent.NAME))
            logger.error(E)
        try:
            module_intent._store_result_in_history()  # 存储到历史记录
        except Exception as E:
            logger.error(E)

        Xcache.del_module_task_by_uuid(task_uuid=msf_module_return_dict.get("uuid"))  # 清理缓存信息
        Notice.send_success("模块: {} {} 执行完成".format(module_intent.NAME, module_intent._target_str))

    @staticmethod
    def store_monitor_from_sub(message=None):
        body = message.get('data')
        try:
            msf_module_return_dict = json.loads(body)
            req = Xcache.get_module_task_by_uuid(task_uuid=msf_module_return_dict.get("uuid"))
        except Exception as E:
            logger.error(E)
            return False

        if req is None:
            logger.error("未找到请求报文")
            logger.error(msf_module_return_dict)
            return False

        try:
            module_intent = req.get('module')
            if module_intent is None:
                logger.error("获取模块失败,body: {}".format(msf_module_return_dict))
                return False
            logger.warning(
                "模块回调:{} job_id: {} uuid: {}".format(module_intent.NAME, msf_module_return_dict.get("job_id"),
                                                     msf_module_return_dict.get("uuid")))
            module_intent._clean_log()  # 清理结果
        except Exception as E:
            logger.error(E)
            return False

        try:
            module_intent.callback(status=msf_module_return_dict.get("status"),
                                   message=msf_module_return_dict.get("message"),
                                   data=msf_module_return_dict.get("data"))
        except Exception as E:
            Notice.send_error("模块 {} 的回调函数callhack运行异常".format(module_intent.NAME))
            logger.error(E)
        Notice.send_info("模块: {} 回调执行完成".format(module_intent.NAME))
        module_intent._store_result_in_history()  # 存储到历史记录

    @staticmethod
    def store_log_from_sub(message=None):
        body = message.get('data')
        try:
            msf_module_logs_dict = json.loads(body)
            Notice.send(f"MSF >> {msf_module_logs_dict.get('content')}", level=msf_module_logs_dict.get("level"))
        except Exception as E:
            logger.error(E)
            return False
