# -*- coding: utf-8 -*-
# @File  : portfwd.py
# @Date  : 2021/2/25
# @Desc  :
import json

from Lib.api import data_return
from Lib.configs import CODE_MSG, PORTFWD_MSG, RPC_SESSION_OPER_SHORT_REQ
from Lib.log import logger
from Lib.method import Method
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.rpcclient import RpcClient


class PortFwd(object):
    @staticmethod
    def list(sessionid=None):
        result_list = PortFwd.list_portfwd()
        if sessionid is None or sessionid == -1:

            context = data_return(200, CODE_MSG.get(200), result_list)
            return context
        else:
            tmplist = []
            try:
                for one in result_list:
                    if one.get('sessionid') == sessionid:
                        tmplist.append(one)
            except Exception as E:
                logger.warning(E)

            context = data_return(200, CODE_MSG.get(200), tmplist)
            return context

    @staticmethod
    def list_portfwd():
        result_list = RpcClient.call(Method.SessionMeterpreterPortFwdList, timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result_list is None:
            return []
        else:
            return result_list

    @staticmethod
    def create(portfwdtype=None, lhost=None, lport=None, rhost=None, rport=None, sessionid=None):
        # 获取不同转发的默认参数
        flag, context = PortFwd._check_host_port(portfwdtype, lhost, lport, rhost, rport)
        if flag is not True:
            return context

        # flag, lportsstr = is_empty_ports(lportint)
        # if flag is not True:
        #       # 端口已占用
        #     context = dict_data_return(CODE, CODE_MSG.get(CODE), {})
        #     return context

        opts = {'TYPE': portfwdtype,
                'LHOST': lhost, 'LPORT': lport, 'RHOST': rhost, 'RPORT': rport,
                'SESSION': sessionid, 'CMD': 'add'}

        result = MSFModule.run(module_type="post", mname="multi/manage/portfwd_api", opts=opts,
                               timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result is None:
            context = data_return(308, PORTFWD_MSG.get(308), {})
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.warning(E)
            context = data_return(301, PORTFWD_MSG.get(301), [])
            return context
        if result_dict.get('status') is True:
            Notice.send_success(f"新增端口转发 SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}")
            context = data_return(201, PORTFWD_MSG.get(201), result_dict.get('data'))
            return context
        else:
            context = data_return(301, PORTFWD_MSG.get(301), [])
            return context

    @staticmethod
    def destory(portfwdtype=None, lhost=None, lport=None, rhost=None, rport=None, sessionid=None):
        if sessionid is not None or sessionid == -1:
            opts = {'TYPE': portfwdtype, 'LHOST': lhost, 'LPORT': lport, 'RHOST': rhost, 'RPORT': rport,
                    'SESSION': sessionid, 'CMD': 'delete'}
            result = MSFModule.run(module_type="post", mname="multi/manage/portfwd_api", opts=opts,
                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(308, PORTFWD_MSG.get(308), {})
                return context
            try:
                result_dict = json.loads(result)
            except Exception as E:
                logger.warning(E)
                context = data_return(302, PORTFWD_MSG.get(302), [])
                return context
            if result_dict.get('status') is True:
                Notice.send_info(f"删除端口转发 SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}")
                context = data_return(204, PORTFWD_MSG.get(204), result_dict.get('data'))
                return context
            else:
                context = data_return(305, PORTFWD_MSG.get(305), [])
                return context
        else:
            context = data_return(306, PORTFWD_MSG.get(306), [])
            return context

    @staticmethod
    def _check_host_port(portfwd_type=None, lhost=None, lport=None, rhost=None, rport=None):
        if portfwd_type not in ['Reverse', 'Forward']:
            context = data_return(306, PORTFWD_MSG.get(306), {})
            return False, context
        if lport is None or rport is None:
            context = data_return(306, PORTFWD_MSG.get(306), {})
            return False, context
        if portfwd_type == "Reverse":
            if lhost is None:
                context = data_return(306, PORTFWD_MSG.get(306), {})
                return False, context
        else:
            if rhost is None:
                context = data_return(306, PORTFWD_MSG.get(306), {})
                return False, context
        return True, None
