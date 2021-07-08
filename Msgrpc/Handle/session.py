# -*- coding: utf-8 -*-
# @File  : session.py
# @Date  : 2021/2/25
# @Desc  :

from Lib.api import data_return
from Lib.configs import Session_MSG, CODE_MSG, RPC_SESSION_OPERTION_API_REQ
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.sessionlib import SessionLib
from Lib.xcache import Xcache
from Msgrpc.serializers import SessionLibSerializer


class Session(object):
    """session信息"""

    @staticmethod
    def list(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, Session_MSG.get(304), {})
            return context
        session_interface = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_interface).data
        context = data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def update(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, Session_MSG.get(304), {})
            return context
        Xcache.set_session_info(sessionid, None)
        session_lib = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_lib).data
        context = data_return(203, Session_MSG.get(203), result)
        return context

    @staticmethod
    def destroy(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, Session_MSG.get(304), {})
            return context
        else:
            params = [sessionid]
            try:
                result = RpcClient.call(Method.SessionStop, params, timeout=RPC_SESSION_OPERTION_API_REQ)
                if result is None:  # 删除超时
                    Notice.send_success(f"{Session_MSG.get(202)} SID: {sessionid}")
                    context = data_return(202, Session_MSG.get(202), {})
                    return context
                elif result.get('result') == 'success':
                    Notice.send_success(f"{Session_MSG.get(201)} SID: {sessionid}")
                    context = data_return(201, Session_MSG.get(201), {})
                    return context
                else:
                    Notice.send_warning(f"{Session_MSG.get(301)} SID: {sessionid}")
                    context = data_return(301, Session_MSG.get(301), {})
                    return context
            except Exception as E:
                logger.error(E)
                Notice.send_warning(f"{Session_MSG.get(301)} SID: {sessionid}")
                context = data_return(301, Session_MSG.get(301), {})
                return context
