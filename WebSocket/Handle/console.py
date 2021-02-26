# -*- coding: utf-8 -*-
# @File  : console.py
# @Date  : 2021/2/26
# @Desc  :
from Lib.log import logger
from Lib.method import Method
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache


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
