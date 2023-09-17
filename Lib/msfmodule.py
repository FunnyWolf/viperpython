# -*- coding: utf-8 -*-
# @File  : msfmodule.py
# @Date  : 2021/2/26
# @Desc  :
import json
import time

from Lib.configs import RPC_JOB_API_REQ, RPC_SESSION_OPER_SHORT_REQ
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
    def run_msf_module_realtime(module_type=None, mname=None, opts=None, runasjob=False,
                                timeout=RPC_SESSION_OPER_SHORT_REQ):
        """实时运行MSF模块"""
        params = [module_type,
                  mname,
                  opts,
                  runasjob,
                  timeout]
        result = RpcClient.call(Method.ModuleExecute, params, timeout=timeout)
        return result

    @staticmethod
    def putin_msf_module_job_queue(msf_module=None):
        """调用msgrpc生成job,放入列表"""

        params = [msf_module.type,
                  msf_module.mname,
                  msf_module.opts,
                  True,  # 强制设置后台运行
                  RPC_JOB_API_REQ  # 超时时间
                  ]

        result = RpcClient.call(Method.ModuleExecute, params, timeout=RPC_JOB_API_REQ)
        if result is None:
            Notice.send_warning(f"渗透服务连接失败,无法执行模块 :{msf_module.NAME_ZH}",
                                f"MSFRPC connection failed and the module could not be executed :<{msf_module.NAME_EN}>")
            return False

        # result 数据格式
        # {'job_id': 3, 'uuid': 'dbcb2530-95b1-0137-5100-000c2966078a', 'module': b'\x80\ub.'}

        if result.get("uuid") is None:
            logger.warning(f"模块实例:{msf_module.NAME_ZH} uuid: {result.get('uuid')} 创建后台任务失败")
            Notice.send_warning(f"模块: {msf_module.NAME_ZH} {msf_module.target_str} 创建后台任务失败",
                                f"Module: <{msf_module.NAME_EN}> {msf_module.target_str} failed to create task")
            return False
        else:
            logger.info(
                f"模块实例放入列表:{msf_module.NAME_ZH} job_id: {result.get('job_id')} uuid: {result.get('uuid')}")

            # 放入请求队列
            msf_module._module_uuid = result.get("uuid")
            req = {
                'broker': msf_module.MODULE_BROKER,
                'uuid': result.get("uuid"),
                'module': msf_module,
                'time': int(time.time()),
                'job_id': result.get("job_id"),
            }
            Xcache.create_module_task(req)
            Notice.send_info(f"模块: {msf_module.NAME_ZH} {msf_module.target_str} 后台运行中",
                             f"Module: <{msf_module.NAME_EN}> {msf_module.target_str} start running")
            return True

    @staticmethod
    def store_result_from_sub(message=None):
        """处理msf模块发送的result信息pub_json_result"""
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
            logger.warning(body)
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
            logger.error(f"获取模块失败,body: {msf_module_return_dict}")
            return False

        # 调用回调函数
        try:
            module_intent.clean_log()  # 清理历史结果
            logger.info(f"模块clean_log:{module_intent.NAME_ZH} "
                        f"job_id: {msf_module_return_dict.get('job_id')} "
                        f"uuid: {msf_module_return_dict.get('uuid')}")
        except Exception as E:
            logger.error(E)
            return False

        try:
            logger.info(f"模块callback start:{module_intent.NAME_ZH} "
                        f"job_id: {msf_module_return_dict.get('job_id')} "
                        f"uuid: {msf_module_return_dict.get('uuid')}")
            module_intent.callback(status=msf_module_return_dict.get("status"),
                                   message=msf_module_return_dict.get("message"),
                                   data=msf_module_return_dict.get("data"))
            logger.info(f"模块callback finish:{module_intent.NAME_ZH} "
                        f"job_id: {msf_module_return_dict.get('job_id')} "
                        f"uuid: {msf_module_return_dict.get('uuid')}")
        except Exception as E:
            Notice.send_exception(f"模块 {module_intent.NAME_ZH} 的回调函数callhack运行异常",
                                  f"Module <{module_intent.NAME_EN}> callback function run exception")
            logger.error(E)
        try:
            module_intent.store_result_in_history()  # 存储到历史记录
            logger.info(f"存储输出到历史记录:{module_intent.NAME_ZH} "
                        f"job_id: {msf_module_return_dict.get('job_id')} "
                        f"uuid: {msf_module_return_dict.get('uuid')}")
        except Exception as E:
            logger.error(E)

        Xcache.del_module_task_by_uuid(task_uuid=msf_module_return_dict.get("uuid"))  # 清理缓存信息
        logger.info(f"清理缓存任务:{module_intent.NAME_ZH} "
                    f"job_id: {msf_module_return_dict.get('job_id')} "
                    f"uuid: {msf_module_return_dict.get('uuid')}")
        Notice.send_info(f"模块: {module_intent.NAME_ZH} {module_intent.target_str} 执行完成",
                         f"Module: <{module_intent.NAME_EN}> {module_intent.target_str} run finish")

    @staticmethod
    def handle_heartbeat_data(message=None):
        """处理msf模块发送的data信息pub_json_data"""
        body = message.get('data')
        try:
            return_dict = json.loads(body)
            data = return_dict.get("data")

            result_jobs = data.get("jobs")
            Xcache.set_msf_job_cache(result_jobs)

            result_sessions = data.get("sessions")
            Xcache.set_msf_sessions_cache(result_sessions)

            # 设置msfrpc存活状态
            Xcache.set_msfrpc_alive()

        except Exception as E:
            logger.error(E)
            logger.warning(body)
            return False

    @staticmethod
    def handle_msfrpc_data(message=None):
        """处理msf模块发送的data信息pub_json_data"""
        body = message.get('data')
        try:
            msf_module_return_dict = json.loads(body)
            req = Xcache.get_module_task_by_uuid(task_uuid=msf_module_return_dict.get("uuid"))
        except Exception as E:
            logger.warning(body)
            logger.error(E)
            return False

        if req is None:
            logger.error("未找到请求报文")
            logger.error(msf_module_return_dict)
            return False

        try:
            module_intent = req.get('module')
            if module_intent is None:
                logger.error(f"获取模块失败,body: {msf_module_return_dict}")
                return False
            logger.warning(
                f"模块回调:{module_intent.NAME_ZH} job_id: {msf_module_return_dict.get('job_id')} uuid: {msf_module_return_dict.get('uuid')}")
            module_intent.clean_log()  # 清理结果
        except Exception as E:
            logger.error(E)
            return False

        try:
            module_intent.callback(status=msf_module_return_dict.get("status"),
                                   message=msf_module_return_dict.get("message"),
                                   data=msf_module_return_dict.get("data"))
        except Exception as E:
            Notice.send_exception(f"模块 {module_intent.NAME_ZH} 的回调函数callback运行异常",
                                  f"Module {module_intent.NAME_ZH} callback run error")
            logger.error(E)

        Notice.send_info(f"模块: {module_intent.NAME_ZH} 回调执行完成",
                         f"Module: <{module_intent.NAME_EN}> callback run finish")
        module_intent.store_result_in_history()  # 存储到历史记录

    @staticmethod
    def store_log_from_sub(message=None):
        """处理msf发送的notice信息print_XXX_redis"""
        body = message.get('data')
        try:
            msf_module_logs_dict = json.loads(body)
            Notice.send(f"MSF >> {msf_module_logs_dict.get('content')}", level=msf_module_logs_dict.get("level"))
        except Exception as E:
            logger.error(E)
            logger.warning(body)
            return False
