# -*- coding: utf-8 -*-
# @File  : montior.py
# @Date  : 2021/2/25
# @Desc  :
import logging
import random
import socket
import time

from apscheduler.schedulers.background import BackgroundScheduler
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from Core.Handle.host import Host
from Core.Handle.setting import Settings
from Core.Handle.uuidjson import UUIDJson
from Lib.Module.moduletemplate import BROKER
from Lib.botmodule import BotModule
from Lib.configs import *
from Lib.file import File
from Lib.log import logger
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.redisclient import RedisClient
from Lib.rpcserver import RPCServer
from Lib.xcache import Xcache
from Msgrpc.Handle.handler import Handler
from PostModule.Handle.postmoduleauto import PostModuleAuto
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from PostModule.Handle.postmodulesingletonscheduler import postModuleSingletonScheduler
from PostModule.Handle.proxyhttpscan import ProxyHttpScan
from WebSocket.Handle.console import Console
from WebSocket.Handle.heartbeat import HeartBeat


class MainMonitor(object):
    BotScheduler: BackgroundScheduler
    MainScheduler: BackgroundScheduler
    HeartBeatScheduler: BackgroundScheduler

    def __init__(self):
        pass

    def start(self):
        try:
            time.sleep(random.random())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 47200))
        except socket.error:
            logger.warning("MainMonitor 已经启动,请勿重复启动")
            return
        # 初始化配置
        try:
            Host.init_on_start()
        except Exception as E:
            logger.exception(E)

        # 加载历史监听
        handler_list = Xcache.get_cache_handlers()
        Handler.recovery_cache_last_handler(handler_list)

        # Xcache初始化部分
        Xcache.init_xcache_on_start()

        # 加载模块配置信息
        PostModuleConfig.load_all_modules_config()

        # 关闭apscheduler的警告
        log = logging.getLogger('apscheduler.scheduler')
        log.setLevel(logging.ERROR)

        self.MainScheduler = BackgroundScheduler(timezone='Asia/Shanghai')
        # sub 唯一线程
        self.MainScheduler.add_job(func=self.subscribe_main_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='subscribe_main_thread')
        # 心跳线程
        self.MainScheduler.add_job(func=self.sub_heartbeat_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_heartbeat_thread')

        # rpc call调用
        self.MainScheduler.add_job(func=self.sub_rpc_call_thread, max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_rpc_call_thread')

        # 定时清理日志
        self.MainScheduler.add_job(func=File.clean_logs, trigger='cron', hour='23', minute='59')
        self.MainScheduler.start()

        self.BotScheduler = BackgroundScheduler(timezone='Asia/Shanghai')
        # msf bot 运行测试线程
        self.BotScheduler.add_job(func=self.run_msf_bot_thread, max_instances=1,
                                  trigger='interval',
                                  seconds=1, id='run_msf_bot_thread')

        # python bot 运行测试线程
        self.BotScheduler.add_job(func=self.run_python_bot_thread, max_instances=3,
                                  trigger='interval',
                                  seconds=1, id='run_python_bot_thread')
        self.BotScheduler.start()

        # 启动自动化定时任务
        postModuleSingletonScheduler.start()

        logger.warning("后台服务启动成功")
        Notice.send_info(f"后台服务启动完成.", "Background service is started.")

    @staticmethod
    def subscribe_main_thread():
        """这个函数必须以线程的方式运行"""

        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{MSF_RPC_RESULT_CHANNEL: MSFModule.store_result_from_sub})
        ps.subscribe(**{MSF_RPC_DATA_CHANNEL: MSFModule.handle_msfrpc_data})
        ps.subscribe(**{MSF_RPC_HEARTBEAT_CHANNEL: MSFModule.handle_heartbeat_data})
        ps.subscribe(**{MSF_RPC_LOG_CHANNEL: MSFModule.store_log_from_sub})
        ps.subscribe(**{VIPER_POSTMODULE_AUTO_CHANNEL: PostModuleAuto.handle_task})
        ps.subscribe(**{VIPER_SEND_SMS_CHANNEL: Settings.send_bot_msg})
        ps.subscribe(**{MSF_RPC_CONSOLE_PRINT: Console.print_output_from_sub})
        ps.subscribe(**{VIPER_RPC_UUID_JSON_DATA: UUIDJson.store_data_from_sub})
        ps.subscribe(**{VIPER_PROXY_HTTP_SCAN_DATA: ProxyHttpScan.store_request_response_from_sub})

        for message in ps.listen():
            if message:
                logger.warning(f"不应获取非空message {message}")

    @staticmethod
    def run_msf_bot_thread():
        # 检查当前MSF任务数量是否大于3个
        task_queue_length = Xcache.get_module_task_length()
        if task_queue_length >= 5:
            return

        req = Xcache.pop_one_from_bot_wait(BROKER.bot_msf_module)
        if req is None:
            return

        module_intent = req.get("module")
        BotModule.run_msf_module(module_intent)

    @staticmethod
    def run_python_bot_thread():
        req = Xcache.pop_one_from_bot_wait(BROKER.bot_python_module)
        if req is None:
            return
        module_intent = req.get("module")
        BotModule.run_python_module(module_intent)

    @staticmethod
    def sub_heartbeat_thread():
        channel_layer = get_channel_layer()

        result = HeartBeat.get_heartbeat_result()
        async_to_sync(channel_layer.group_send)(
            "heartbeat",
            {
                'type': 'send.message',
                'message': result
            }
        )

    @staticmethod
    def sub_rpc_call_thread():
        RPCServer().run()
