# -*- coding: utf-8 -*-
# @File  : transport.py
# @Date  : 2021/2/25
# @Desc  :
import base64
import json
import time

from Lib.api import data_return
from Lib.configs import TRANSPORT_MSG_ZH, CODE_MSG_ZH, RPC_SESSION_OPER_SHORT_REQ, TRANSPORT_MSG_EN, CODE_MSG_EN
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Msgrpc.Handle.handler import Handler


class Transport(object):
    @staticmethod
    def list(sessionid=None):

        if sessionid is None or sessionid == -1:
            context = data_return(306, {}, TRANSPORT_MSG_ZH.get(306), TRANSPORT_MSG_EN.get(306))
            return context
        else:
            result_list = Transport.list_transport(sessionid)

            context = data_return(200, result_list, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context

    @staticmethod
    def list_transport(sessionid):
        tmp_enum_list = Handler.list_handler_config()
        result_list = RpcClient.call(Method.SessionMeterpreterTransportList, [sessionid],
                                     timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result_list is None:
            transports = []
            return {'session_exp': 0, 'transports': transports, "handlers": tmp_enum_list}
        else:
            result_list["handlers"] = tmp_enum_list
            transports = result_list.get("transports")
            current_transport_url = None
            if len(transports) > 0:
                transports[0]["active"] = True
                current_transport_url = transports[0].get("url")

            i = 0
            for transport in transports:
                transport["tid"] = i
                i += 1
                if transport.get("url") == current_transport_url:
                    transport["active"] = True

                if transport.get("cert_hash") is not None:
                    cert_hash = transport.get("cert_hash")
                    transport["cert_hash"] = base64.b64encode(cert_hash.encode("utf-8"))

            def get_url(data):
                return data.get("url")

            transports.sort(key=get_url)
            return result_list

    @staticmethod
    def create(sessionid=None, handler=None):
        # 获取不同转发的默认参数
        try:
            handleropts = json.loads(handler)
        except Exception as E:
            logger.exception(E)
            logger.warning(handler)
            context = data_return(303, [], TRANSPORT_MSG_ZH.get(303), TRANSPORT_MSG_EN.get(303))
            return context

        opts = {
            "uuid": None,
            "transport": None,
            "lhost": None,
            "lport": None,
            "ua": None,
            "proxy_host": None,
            "proxy_port": None,
            "proxy_type": None,
            "proxy_user": None,
            "proxy_pass": None,
            "comm_timeout": None,
            "session_exp": None,
            "retry_total": None,
            "retry_wait": None,
            "cert": None,
            "luri": None,

        }

        handler_payload = handleropts.get("PAYLOAD")
        if "reverse_tcp" in handler_payload:
            opts["transport"] = "reverse_tcp"
        elif "reverse_https" in handler_payload:
            opts["transport"] = "reverse_https"
        elif "reverse_http" in handler_payload:
            opts["transport"] = "reverse_http"
        elif "bind_tcp" in handler_payload:
            opts["transport"] = "bind_tcp"
        else:
            context = data_return(303, [], TRANSPORT_MSG_ZH.get(303), TRANSPORT_MSG_EN.get(303))
            return context

        opts["uuid"] = handleropts.get("PayloadUUIDSeed")
        opts["lhost"] = handleropts.get("LHOST")
        opts["lport"] = handleropts.get("LPORT")
        opts["ua"] = handleropts.get("HttpUserAgent")
        opts["proxy_host"] = handleropts.get("HttpProxyHost")
        opts["proxy_port"] = handleropts.get("HttpProxyPort")
        opts["proxy_type"] = handleropts.get("HttpProxyType")
        opts["proxy_user"] = handleropts.get("HttpProxyUser")
        opts["proxy_pass"] = handleropts.get("HttpProxyPass")
        opts["comm_timeout"] = handleropts.get("SessionCommunicationTimeout")
        opts["session_exp"] = handleropts.get("SessionExpirationTimeout")
        opts["retry_total"] = handleropts.get("SessionRetryTotal")
        opts["retry_wait"] = handleropts.get("SessionRetryWait")
        opts["cert"] = handleropts.get("HandlerSSLCert")

        opts["luri"] = handleropts.get("LURI")
        result_flag = RpcClient.call(Method.SessionMeterpreterTransportAdd, [sessionid, opts],
                                     timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result_flag:
            Notice.send_info(f"新增传输 SID:{sessionid}", f"Add transport:{sessionid}")

            context = data_return(201, {}, TRANSPORT_MSG_ZH.get(201), TRANSPORT_MSG_EN.get(201))
            return context
        else:
            context = data_return(301, [], TRANSPORT_MSG_ZH.get(301), TRANSPORT_MSG_EN.get(301))
            return context

    @staticmethod
    def update(sessionid=None, action=None, sleep=0):
        if sessionid is None or sessionid <= 0:
            context = data_return(306, {}, TRANSPORT_MSG_ZH.get(306), TRANSPORT_MSG_EN.get(306))
            return context
        if action == "next":
            result_flag = RpcClient.call(Method.SessionMeterpreterTransportNext, [sessionid],
                                         timeout=RPC_SESSION_OPER_SHORT_REQ)
        elif action == "prev":
            result_flag = RpcClient.call(Method.SessionMeterpreterTransportPrev, [sessionid],
                                         timeout=RPC_SESSION_OPER_SHORT_REQ)
        elif action == "sleep":
            result_flag = RpcClient.call(Method.SessionMeterpreterTransportSleep, [sessionid, sleep],
                                         timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result_flag:
                reconnect_time = time.time() + sleep
                Notice.send_warning(
                    f'切换Session到休眠 SID:{sessionid} 重连时间: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reconnect_time))}',
                    f'Switch session to sleep SID:{sessionid} Reconnect time: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(reconnect_time))}')

                context = data_return(203, {}, TRANSPORT_MSG_ZH.get(203), TRANSPORT_MSG_EN.get(203))
                return context
            else:
                context = data_return(305, [], TRANSPORT_MSG_ZH.get(305), TRANSPORT_MSG_EN.get(305))
                return context

        else:
            result_flag = False
        if result_flag:
            Notice.send_info(f"切换传输完成 SID:{sessionid}", f"Switch transport successfully SID:{sessionid}")
            context = data_return(202, {}, TRANSPORT_MSG_ZH.get(202), TRANSPORT_MSG_EN.get(202))
            return context
        else:
            context = data_return(302, [], TRANSPORT_MSG_ZH.get(302), TRANSPORT_MSG_EN.get(302))
            return context

    @staticmethod
    def destory(query_params):
        opts = {
            "uuid": None,
            "transport": None,
            "lhost": None,
            "lport": None,
            "ua": None,
            "proxy_host": None,
            "proxy_port": None,
            "proxy_type": None,
            "proxy_user": None,
            "proxy_pass": None,
            "comm_timeout": None,
            "session_exp": None,
            "retry_total": None,
            "retry_wait": None,
            "cert": None,
            "luri": None,
        }

        sessionid = query_params.get("sessionid")

        opts["url"] = query_params.get("url")

        result_flag = RpcClient.call(Method.SessionMeterpreterTransportRemove, [sessionid, opts],
                                     timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result_flag:
            Notice.send_info(f"删除传输 SID:{sessionid}", f"Delete transport:{sessionid}")
            context = data_return(204, {}, TRANSPORT_MSG_ZH.get(204), TRANSPORT_MSG_EN.get(204))
            return context
        else:
            context = data_return(304, [], TRANSPORT_MSG_ZH.get(304), TRANSPORT_MSG_EN.get(304))
            return context
