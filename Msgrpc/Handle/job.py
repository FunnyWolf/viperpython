# -*- coding: utf-8 -*-
# @File  : job.py
# @Date  : 2021/2/25
# @Desc  :
import copy
import time

from Lib.Module.configs import HANDLER_OPTION, BROKER
from Lib.api import data_return
from Lib.apsmodule import aps_module
from Lib.configs import Job_MSG_ZH, CODE_MSG_ZH, RPC_FRAMEWORK_API_REQ, Job_MSG_EN, CODE_MSG_EN, \
    MSF_MODULE_CALLBACK_WAIT_SENCOND
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache
from Msgrpc.serializers import PostModuleSerializer, BotModuleSerializer


class Job(object):

    @staticmethod
    def list_jobs():
        """获取后台任务列表,包括msf任务及本地多模块任务"""

        msf_jobs_dict = Job.list_msfrpc_jobs()
        if msf_jobs_dict is None:  # msfrpc临时异常
            uncheck = True  # 跳过任务检查
            msf_jobs_dict = {}
        else:
            uncheck = False

        reqs = Xcache.list_module_tasks()
        reqs_temp = []
        for req in reqs:
            if uncheck or req.get("job_id") is None or msf_jobs_dict.get(str(req.get("job_id"))) is not None:
                req["moduleinfo"] = PostModuleSerializer(req.get("module"), many=False).data
                module_intent = req.pop("module")  # 弹出module实例
                req["opts"] = module_intent.get_readable_opts()
                reqs_temp.append(req)
                continue
            else:
                # 清除失效的任务
                if int(time.time()) - req.get("time") >= MSF_MODULE_CALLBACK_WAIT_SENCOND:
                    logger.error(f"清除失效的任务: {req.get('module').NAME_ZH}")
                    logger.error(req)
                    Xcache.del_module_task_by_uuid(req.get("uuid"))
                else:
                    # 如果创建时间不足5秒,则等待callback处理数据
                    req["moduleinfo"] = PostModuleSerializer(req.get("module"), many=False).data
                    req["moduleinfo"]['_custom_param'] = Job._deal_dynamic_param(req["moduleinfo"]['_custom_param'])
                    req.pop("module")
                    reqs_temp.append(req)
                    continue
        return reqs_temp

    @staticmethod
    def _deal_dynamic_param(_custom_param=None):
        """处理handler及凭证等动态变化参数,返回处理后参数列表"""
        if _custom_param is None:
            return None
        import json
        if _custom_param.get(HANDLER_OPTION.get("name")) is not None:
            new_option = {}
            try:
                old_option = json.loads(_custom_param.get(HANDLER_OPTION.get("name")))
            except Exception as E:
                logger.exception(E)
                logger.warning(_custom_param)
            new_option["PAYLOAD"] = old_option.get("PAYLOAD")
            new_option["LPORT"] = old_option.get("LPORT")

            if old_option.get("LHOST") is not None:
                new_option["LHOST"] = old_option.get("LHOST")

            if old_option.get("RHOST") is not None:
                new_option["RHOST"] = old_option.get("RHOST")

            if old_option.get("LURI") is not None:
                new_option["LURI"] = old_option.get("LURI")

            if old_option.get("HandlerSSLCert") is not None:
                new_option["HandlerSSLCert"] = old_option.get("HandlerSSLCert")

            if old_option.get("RC4PASSWORD") is not None:
                new_option["RC4PASSWORD"] = old_option.get("RC4PASSWORD")

            if old_option.get("proxies") is not None:
                new_option["proxies"] = old_option.get("proxies")

            _custom_param[HANDLER_OPTION.get("name")] = json.dumps(new_option)

        return _custom_param

    @staticmethod
    def list_bot_wait():
        bot_wait_show = {}
        reqs_temp = []
        reqs = Xcache.list_bot_wait()

        for req in reqs:
            req["moduleinfo"] = BotModuleSerializer(req.get("module"), many=False).data
            req.pop("module")  # 弹出module实例
            req_group_uuid = req.get("group_uuid")
            req_moduleinfo = req.get("moduleinfo")
            if bot_wait_show.get(req_group_uuid) is None:
                req_tmp = copy.deepcopy(req)
                req_tmp["ip_list"] = [req_moduleinfo.get("_ip")]
                bot_wait_show[req_group_uuid] = req_tmp
            else:
                bot_wait_show[req_group_uuid]["ip_list"].append(req_moduleinfo.get("_ip"))
        for group_uuid in bot_wait_show:
            reqs_temp.append(bot_wait_show.get(group_uuid))
        return reqs_temp

    @staticmethod
    def list_msfrpc_jobs():
        infos = Xcache.get_msf_job_cache()
        return infos

    @staticmethod
    def is_msf_job_alive(job_id):
        time.sleep(1)
        try:
            result = Xcache.get_msf_job_cache()
            if result is None:
                return False
            else:
                if result.get(str(job_id)) is not None:
                    return True
                else:
                    return False
        except Exception as E:
            logger.error(E)
            return False

    @staticmethod
    def destroy_adv_job(task_uuid=None, job_id=None, broker=None):
        try:
            if broker == BROKER.post_python_job:
                flag = aps_module.delete_job_by_uuid(task_uuid)
                if flag is not True:
                    context = data_return(304, {}, Job_MSG_ZH.get(304), Job_MSG_EN.get(304))
                    return context
                else:
                    context = data_return(204, {"uuid": task_uuid, "job_id": job_id}, Job_MSG_ZH.get(204),
                                          Job_MSG_EN.get(204))
                    return context
            elif broker == BROKER.post_msf_job:
                req = Xcache.get_module_task_by_uuid(task_uuid=task_uuid)
                common_module_instance = req.get("module")
                Xcache.del_module_task_by_uuid(task_uuid)
                params = [job_id]
                result = RpcClient.call(Method.JobStop, params, timeout=RPC_FRAMEWORK_API_REQ)
                if result is None:
                    context = data_return(305, {}, Job_MSG_ZH.get(305), Job_MSG_EN.get(305))
                    return context
                if result.get('result') == 'success':
                    # 发送通知
                    Notice.send_info(
                        f"模块: {common_module_instance.NAME_ZH} {common_module_instance.target_str} 手动删除完成",
                        f"Module: <{common_module_instance.NAME_EN}> {common_module_instance.target_str} manually delete")
                    context = data_return(204, {"uuid": task_uuid, "job_id": job_id}, Job_MSG_ZH.get(204),
                                          Job_MSG_EN.get(204))
                    return context
                else:
                    context = data_return(304, {}, Job_MSG_ZH.get(304), Job_MSG_EN.get(304))
                    return context
            elif broker == BROKER.bot_msf_module or broker == BROKER.bot_python_module:
                flag = Xcache.del_bot_wait_by_group_uuid(task_uuid)
                if flag is not True:
                    context = data_return(304, {}, Job_MSG_ZH.get(304), Job_MSG_EN.get(304))
                    return context
                else:
                    context = data_return(204, {"uuid": task_uuid}, Job_MSG_ZH.get(204), Job_MSG_EN.get(204))
                    return context
            else:
                context = data_return(304, {}, Job_MSG_ZH.get(304), Job_MSG_EN.get(304))
                return context

        except Exception as E:
            logger.error(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
            return context

    @staticmethod
    def destroy(id=None):
        try:
            params = [id]
            result = RpcClient.call(Method.JobStop, params, timeout=RPC_FRAMEWORK_API_REQ)
            if result is None:
                return False
            if result.get('result') == 'success':
                return True
            else:
                return False
        except Exception as E:
            logger.error(E)
            return False
