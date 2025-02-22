# -*- coding: utf-8 -*-
# @File  : rpcserver.py
# @Date  : 2021/10/30
# @Desc  :
import json

from Lib.log import logger
from Lib.redisclient import RedisClient
from Lib.xcache import Xcache
from Msgrpc.Handle.ipfilter import IPFilter


class RPCServer(object):
    """Executes function calls received from a Redis queue."""

    def __init__(self):
        self.redis_server = RedisClient.get_result_connection()
        self.message_queue = "rpcviper"

    def run(self):
        # Flush the message queue.
        self.redis_server.delete(self.message_queue)
        while True:
            message_queue, message = self.redis_server.blpop(self.message_queue)
            message_queue = message_queue.decode()
            if message_queue != self.message_queue:
                logger.warning(f"message_queue 错误: {message_queue} {self.message_queue}")
                continue
            try:
                rpc_request = json.loads(message.decode())
                function_call = rpc_request.get('function_call')
                response_queue = rpc_request.get('response_queue')
                function = function_call.get("function")
                kwargs = function_call.get("kwargs")
            except Exception as E:
                logger.warning("请求解析失败")
                logger.exception(E)
                logger.warning(message)
                continue
            rpc_response = self.function_map(function, kwargs)
            self.redis_server.rpush(response_queue, json.dumps(rpc_response))

    def function_map(self, function, kwargs):
        if function == "IPFilter.is_allow":
            try:
                return IPFilter.is_allow(**kwargs)
            except Exception as E:
                logger.exception(E)
                return None
        elif function == "Setting.dnslog_base":
            conf = Xcache.get_dnslog_conf()
            dnslog_base = conf.get("dnslog_base")
            return dnslog_base
        else:
            logger.error(f"未知的rpc调用: {function}")
            return None
