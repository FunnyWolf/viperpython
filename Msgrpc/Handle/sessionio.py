# -*- coding: utf-8 -*-
# @File  : sessionio.py
# @Date  : 2021/2/25
# @Desc  :
from Lib.api import data_return
from Lib.configs import SessionIO_MSG_ZH, METERPRETER_PROMPT, CODE_MSG_ZH, RPC_SESSION_OPER_SHORT_REQ, CODE_MSG_EN, \
    SessionIO_MSG_EN
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
                command = user_input[len('shell'):].strip()
                if len(command) == 0:
                    new_bufer = "\nNot support switch to Dos/Bash,input like\'shell whoami\' to run os cmd.\n"
                    result = Xcache.add_sessionio_cache(ipaddress, new_bufer)

                    context = data_return(200, result, SessionIO_MSG_ZH.get(200), SessionIO_MSG_EN.get(200))
                    return context
                else:
                    user_input = f"shell -c '{command}'"

            if user_input.startswith('exit'):
                params = [sessionid]
                result = RpcClient.call(Method.SessionMeterpreterSessionKill, params,
                                        timeout=RPC_SESSION_OPER_SHORT_REQ)

                context = data_return(203, result, SessionIO_MSG_ZH.get(203), SessionIO_MSG_EN.get(203))
                return context

            params = [sessionid, user_input]
            result = RpcClient.call(Method.SessionMeterpreterWrite, params, timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(305, {}, SessionIO_MSG_ZH.get(305), SessionIO_MSG_EN.get(305))
            elif result.get('result') == 'success':
                new_bufer = f"{METERPRETER_PROMPT}{user_input}\n"
                result = Xcache.add_sessionio_cache(ipaddress, new_bufer)
                context = data_return(200, result, SessionIO_MSG_ZH.get(200), SessionIO_MSG_EN.get(200))
            else:
                context = data_return(305, {}, SessionIO_MSG_ZH.get(305), SessionIO_MSG_EN.get(305))
        except Exception as E:
            logger.error(E)
            context = data_return(306, {}, SessionIO_MSG_ZH.get(306), SessionIO_MSG_EN.get(306))
        return context

    @staticmethod
    def update(ipaddress=None, sessionid=None):
        old_result = Xcache.get_sessionio_cache(ipaddress)
        if sessionid is None or sessionid == -1:
            context = data_return(202, old_result, SessionIO_MSG_ZH.get(202), SessionIO_MSG_EN.get(202))
            return context
        try:
            params = [sessionid]
            result = RpcClient.call(Method.SessionMeterpreterRead, params, timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None or (isinstance(result, dict) is not True):
                context = data_return(303, old_result, SessionIO_MSG_ZH.get(303), SessionIO_MSG_EN.get(303))
                return context
            new_bufer = result.get('data')
            result = Xcache.add_sessionio_cache(ipaddress, new_bufer)
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))  # code特殊处理
        except Exception as E:
            logger.error(E)
            context = data_return(306, old_result, SessionIO_MSG_ZH.get(405), SessionIO_MSG_EN.get(405))
        return context

    @staticmethod
    def destroy(ipaddress=None):
        """清空历史记录"""
        result = Xcache.del_sessionio_cache(ipaddress)
        context = data_return(204, result, SessionIO_MSG_ZH.get(204), SessionIO_MSG_EN.get(204))
        return context
