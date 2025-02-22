# -*- coding: utf-8 -*-
# @File  : console.py
# @Date  : 2021/2/26
# @Desc  :
import base64
import json

import chardet
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from Lib.configs import RPC_FRAMEWORK_API_REQ
from Lib.log import logger
from Lib.method import Method
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache


class Console(object):
    def __init__(self):
        pass

    @staticmethod
    def get_active_console():
        result = RpcClient.call(Method.ConsoleList, [], timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            Xcache.set_console_id(None)
            return False
        else:
            consoles = result.get("consoles")
            if len(consoles) == 0:
                consoles_create_opt = {"SkipDatabaseInit": True, 'AllowCommandPassthru': False}
                result = RpcClient.call(Method.ConsoleCreate, [consoles_create_opt], timeout=RPC_FRAMEWORK_API_REQ)
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
        result = RpcClient.call(Method.ConsoleList, [], timeout=RPC_FRAMEWORK_API_REQ)
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
                    RpcClient.call(Method.ConsoleDestroy, params, timeout=RPC_FRAMEWORK_API_REQ)
            result = RpcClient.call(Method.ConsoleCreate, timeout=RPC_FRAMEWORK_API_REQ)
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

        params = [cid, data.replace("\r\n", "\n")]
        result = RpcClient.call(Method.ConsoleWrite, params, timeout=RPC_FRAMEWORK_API_REQ)
        if result is None or result.get("result") == "failure":
            get_active_console_result = Console.get_active_console()
            if get_active_console_result:
                cid = Xcache.get_console_id()
                params = [cid, data.replace("\r\n", "\n")]
                result = RpcClient.call(Method.ConsoleWrite, params, timeout=RPC_FRAMEWORK_API_REQ)
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
        result = RpcClient.call(Method.ConsoleRead, params, timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            return False, {}
        elif result.get("result") == "failure":
            logger.warning(f"Cid: {cid}错误")
            return False, {}
        else:
            return True, result

    @staticmethod
    def tabs(line=None):
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid, line]
        result = RpcClient.call(Method.ConsoleTabs, params, timeout=RPC_FRAMEWORK_API_REQ)
        if result is None or result.get("result") == "failure":
            logger.warning(f"Cid: {cid}错误")
            return False, {}
        else:
            return True, result

    @staticmethod
    def session_detach():
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid]
        result = RpcClient.call(Method.ConsoleSessionDetach, params, timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            return False, {}
        elif result.get("result") == "failure":
            logger.warning(f"Cid: {cid}错误")
            return False, {}
        else:
            return True, result

    @staticmethod
    def session_kill():
        cid = Xcache.get_console_id()
        if cid is None:
            return False, {}
        params = [cid]
        result = RpcClient.call(Method.ConsoleSessionKill, params, timeout=RPC_FRAMEWORK_API_REQ)
        if result is None:
            return False, {}
        elif result.get("result") == "failure":
            logger.warning(f"Cid: {cid}错误")
            return False, {}
        else:
            return True, result

    @staticmethod
    def print_output_from_sub(message=None):
        """处理msf模块发送的data信息pub_json_data"""
        body = message.get('data')
        try:
            msf_module_return_dict = json.loads(body)
            prompt = msf_module_return_dict.get("prompt")
            output = base64.b64decode(msf_module_return_dict.get("message"))
            chardet_result = chardet.detect(output)
            try:
                output = output.decode(chardet_result['encoding'] or 'utf-8', 'ignore')
            except UnicodeDecodeError as e:
                output = output.decode('utf-8', 'ignore')
            output = output.replace("\n", "\r\n")
            message = {}
            if len(output) == 0:
                message['status'] = 0
                message['data'] = f"{prompt}"
            else:
                message['status'] = 0
                message['data'] = f"{output}"

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "msfconsole",
                {
                    'type': 'send.message',
                    'message': json.dumps(message)
                }
            )

        except Exception as E:
            logger.exception(E)
            logger.warning(body)
            return False
