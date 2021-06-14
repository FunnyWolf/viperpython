# -*- coding: utf-8 -*-
# @File  : montior.py
# @Date  : 2021/2/25
# @Desc  :
import datetime
import logging
import socket

from apscheduler.schedulers.background import BackgroundScheduler
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from Core.Handle.setting import Settings
from Lib.Module.moduletemplate import BROKER
from Lib.configs import *
from Lib.log import logger
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.redisclient import RedisClient
from Lib.xcache import Xcache
from Msgrpc.Handle.handler import Handler
from PostModule.Handle.postmoduleauto import PostModuleAuto
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from WebSocket.Handle.heartbeat import HeartBeat


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

        # postmoduleauto处理线程
        self.MainScheduler.add_job(func=self.sub_postmodule_auto_handle_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='sub_postmodule_auto_handle_thread')

        # bot 运行测试线程
        self.MainScheduler.add_job(func=self.run_bot_wait_list, max_instances=1,
                                   trigger='interval',
                                   seconds=1, id='run_bot_wait_list')

        # 恢复上次运行保存的监听
        self.MainScheduler.add_job(func=Handler.recovery_cache_last_handler,
                                   trigger='date',
                                   next_run_time=datetime.datetime.now() + datetime.timedelta(seconds=10),
                                   args=[handler_list],
                                   id='recovery_cache_last_handler')

        self.MainScheduler.start()

        logger.warning("后台服务启动成功")
        Notice.send_success(f"后台服务启动成功,10秒后开始加载历史监听.")

    @staticmethod
    def run_bot_wait_list():

        # 检查当前任务数量是否大于3个
        task_queue_length = Xcache.get_module_task_length()
        if task_queue_length >= 3:
            return

        req = Xcache.pop_one_from_bot_wait()
        if req is None:
            return

        broker = req.get("broker")
        module_intent = req.get("module")
        if broker == BROKER.bot_msf_module:
            MSFModule.run_bot_msf_module(module_intent)
        else:
            logger.error("unknow broker")

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
    def sub_postmodule_auto_handle_thread():
        """这个函数必须以线程的方式运行"""

        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{VIPER_POSTMODULE_AUTO_CHANNEL: PostModuleAuto.handle_task})
        for message in ps.listen():
            if message:
                logger.warning("不应获取非空message {}".format(message))

    @staticmethod
    def sub_send_sms_thread():
        """这个函数必须以线程的方式运行"""

        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return
        ps = rcon.pubsub(ignore_subscribe_messages=True)
        ps.subscribe(**{VIPER_SEND_SMS_CHANNEL: Settings._send_bot_msg})
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
        """这个函数必须以线程的方式运行,监控msf发送的redis消息"""
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
