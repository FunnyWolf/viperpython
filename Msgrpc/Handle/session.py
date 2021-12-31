# -*- coding: utf-8 -*-
# @File  : session.py
# @Date  : 2021/2/25
# @Desc  :

from Lib.api import data_return
from Lib.configs import Session_MSG_ZH, CODE_MSG_ZH, RPC_SESSION_OPER_SHORT_REQ, CODE_MSG_EN, Session_MSG_EN
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
            context = data_return(304, {}, Session_MSG_ZH.get(304), Session_MSG_EN.get(304))
            return context
        session_interface = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_interface).data
        context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def update(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, {}, Session_MSG_ZH.get(304), Session_MSG_EN.get(304))
            return context
        Xcache.set_session_info(sessionid, None)
        session_lib = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_lib).data
        context = data_return(203, result, Session_MSG_ZH.get(203), Session_MSG_EN.get(203))
        return context

    @staticmethod
    def destroy(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, {}, Session_MSG_ZH.get(304), Session_MSG_EN.get(304))
            return context
        else:
            params = [sessionid]
            try:
                result = RpcClient.call(Method.SessionStop, params, timeout=RPC_SESSION_OPER_SHORT_REQ)
                if result is None:  # 删除超时
                    Notice.send_info(f"{Session_MSG_ZH.get(202)} SID: {sessionid}",
                                     f"{Session_MSG_EN.get(202)} SID: {sessionid}")
                    context = data_return(202, {}, Session_MSG_ZH.get(202), Session_MSG_EN.get(202))
                    return context
                elif result.get('result') == 'success':
                    Notice.send_info(f"{Session_MSG_ZH.get(201)} SID: {sessionid}",
                                     f"{Session_MSG_EN.get(201)} SID: {sessionid}")
                    context = data_return(201, {}, Session_MSG_ZH.get(201), Session_MSG_EN.get(201))
                    return context
                else:
                    Notice.send_warning(f"{Session_MSG_ZH.get(301)} SID: {sessionid}",
                                        f"{Session_MSG_EN.get(301)} SID: {sessionid}")
                    context = data_return(301, {}, Session_MSG_ZH.get(301), Session_MSG_EN.get(301))
                    return context
            except Exception as E:
                logger.error(E)
                Notice.send_warning(f"{Session_MSG_ZH.get(301)} SID: {sessionid}",
                                    f"{Session_MSG_EN.get(301)} SID: {sessionid}")
                context = data_return(301, {}, Session_MSG_ZH.get(301), Session_MSG_EN.get(301))
                return context
