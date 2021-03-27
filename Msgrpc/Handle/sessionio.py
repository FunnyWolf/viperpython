# -*- coding: utf-8 -*-
# @File  : sessionio.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.api import data_return
from Lib.configs import SessionIO_MSG, METERPRETER_PROMPT, CODE_MSG
from Lib.log import logger
from Lib.method import Method
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache


class SessionIO(object):

    @staticmethod
    def create(ipaddress=None, sessionid=None, user_input=None):
        try:
            user_input = user_input.strip()

            if user_input.startswith('shell'):
                command = user_input[len('shell'):]
                if len(command) == 0:
                    new_bufer = "\n{}\n".format(
                        "Not support switch to Dos/Bash,input like\"shell whoami\" to run os cmd.")
                    result = Xcache.add_sessionio_cache(ipaddress, new_bufer)

                    context = data_return(200, SessionIO_MSG.get(200), result)
                    return context
                else:
                    user_input = f"shell -c '{command}'"

            if user_input.startswith('exit'):
                params = [sessionid]
                result = RpcClient.call(Method.SessionMeterpreterSessionKill, params)

                context = data_return(203, SessionIO_MSG.get(203), result)
                return context

            params = [sessionid, user_input]
            result = RpcClient.call(Method.SessionMeterpreterWrite, params)
            if result is None:
                context = data_return(305, SessionIO_MSG.get(305), {})
            elif result.get('result') == 'success':
                new_bufer = "{}{}\n".format(METERPRETER_PROMPT, user_input)
                result = Xcache.add_sessionio_cache(ipaddress, new_bufer)
                context = data_return(200, SessionIO_MSG.get(200), result)
            else:
                context = data_return(305, SessionIO_MSG.get(305), {})
        except Exception as E:
            logger.error(E)
            context = data_return(306, SessionIO_MSG.get(306), {})
        return context

    @staticmethod
    def update(ipaddress=None, sessionid=None):
        old_result = Xcache.get_sessionio_cache(ipaddress)
        if sessionid is None or sessionid == -1:
            context = data_return(202, SessionIO_MSG.get(202), old_result)
            return context
        try:
            params = [sessionid]
            result = RpcClient.call(Method.SessionMeterpreterRead, params)
            if result is None or (isinstance(result, dict) is not True):
                context = data_return(303, SessionIO_MSG.get(303), old_result)
                return context
            new_bufer = result.get('data')
            result = Xcache.add_sessionio_cache(ipaddress, new_bufer)
            context = data_return(200, CODE_MSG.get(200), result)  # code特殊处理
        except Exception as E:
            logger.error(E)
            context = data_return(306, SessionIO_MSG.get(405), old_result)
        return context

    @staticmethod
    def destroy(ipaddress=None):
        """清空历史记录"""
        result = Xcache.del_sessionio_cache(ipaddress)
        context = data_return(204, SessionIO_MSG.get(204), result)
        return context
