# -*- coding: utf-8 -*-
# @File  : rpcserver.py
# @Date  : 2021/10/30
# @Desc  :
import json
import subprocess
import time

from Lib.api import random_str
from Lib.configs import WAFCHECK
from Lib.log import logger
from Lib.redisclient import RedisClient


class RpcCall(object):

    def __init__(self):
        pass

    @staticmethod
    def rpc_call(worker, timeout=3600, **kwargs):
        rcon = RedisClient.get_result_connection()
        if rcon is None:
            return None

        request_queue = f"{worker}:rpc:{random_str(32)}"
        response_queue = f"{worker}:rpc:{random_str(32)}"

        rpc_raw_request = json.dumps({'kwargs': kwargs})

        logger.info(f"RPC rpush queue {request_queue} {response_queue}")
        logger.info(f"RPC rpush request {rpc_raw_request}")

        # request
        try:
            rcon.rpush(request_queue, rpc_raw_request)
            start_time = int(time.time())
        except Exception as E:
            logger.exception(E)
            return None

        # run
        if worker == WAFCHECK:
            RpcCall.start_worker_wafcheck(request_queue, response_queue)
        else:
            logger.error(f"Unknown worker : {worker}")
            return None

        # response
        try:
            worker, rpc_raw_response = rcon.blpop(response_queue, timeout)
            logger.info(f"RPC blpop {worker}:{rpc_raw_response}")
            logger.info(f"Time use: {int(time.time()) - start_time}")
            if rpc_raw_response is None:
                logger.warning(f"rpc_raw_response is None rpc_raw_response:{rpc_raw_request}")
                rcon.lrem(worker, 0, rpc_raw_request)
                return None
            rpc_response = json.loads(rpc_raw_response.decode())
            return rpc_response
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def start_worker_wafcheck(request_queue, response_queue):
        python3 = "python3.12"
        script = "/root/viper/Worker/wafcheck.py"
        try:
            subprocess.Popen(
                [python3, script, request_queue, response_queue],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"Command '{" ".join([python3, script, request_queue, response_queue])}' is running in the background.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running command: {e}")
