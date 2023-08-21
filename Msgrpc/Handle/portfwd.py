# -*- coding: utf-8 -*-
# @File  : portfwd.py
# @Date  : 2021/2/25
# @Desc  :
import json

from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, PORTFWD_MSG_ZH, RPC_SESSION_OPER_SHORT_REQ, CODE_MSG_EN, PORTFWD_MSG_EN
from Lib.log import logger
from Lib.method import Method
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache


class PortFwd(object):
    @staticmethod
    def list(sessionid=None):
        result_list = PortFwd.list_portfwd()
        if sessionid is None or sessionid == -1:
            context = data_return(200, result_list, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context
        else:
            tmplist = []
            try:
                for one in result_list:
                    if one.get('sessionid') == sessionid:
                        tmplist.append(one)
            except Exception as E:
                logger.warning(E)

            context = data_return(200, tmplist, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context

    @staticmethod
    def list_portfwd():
        result_list = RpcClient.call(Method.SessionMeterpreterPortFwdList, timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result_list is None:
            return []
        else:
            default_lhost = Xcache.get_lhost_config().get("lhost")
            if default_lhost is None:
                default_lhost = "vps_ip"
            for one in result_list:
                if one.get('type') == "Forward":
                    tip = f"Hacker -> {default_lhost}:{one.get('lport')} => {one.get('rhost')}:{one.get('rport')}"
                else:
                    tip = f"Payload -> {one.get('rhost')}:{one.get('rport')} => {one.get('lhost')}:{one.get('lport')}"
                one['tip'] = tip
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
        #     context = dict_data_return(CODE, CODE_MSG_ZH.get(CODE), {})
        #     return context

        opts = {'TYPE': portfwdtype,
                'LHOST': lhost, 'LPORT': lport, 'RHOST': rhost, 'RPORT': rport,
                'SESSION': sessionid, 'CMD': 'add'}

        result = MSFModule.run_msf_module_realtime(module_type="post", mname="multi/manage/portfwd_api", opts=opts,
                                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result is None:
            context = data_return(308, {}, PORTFWD_MSG_ZH.get(308), PORTFWD_MSG_EN.get(308))
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.exception(E)
            logger.warning(result)
            context = data_return(301, [], PORTFWD_MSG_ZH.get(301), PORTFWD_MSG_EN.get(301))
            return context
        if result_dict.get('status') is True:
            Notice.send_info(f"新增端口转发成功 SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}",
                             f"Create portfwd successfully SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}")
            context = data_return(201, result_dict.get('data'), PORTFWD_MSG_ZH.get(201), PORTFWD_MSG_EN.get(201))
            return context
        else:
            context = data_return(301, [], PORTFWD_MSG_ZH.get(301), PORTFWD_MSG_EN.get(301))
            return context

    @staticmethod
    def destory(portfwdtype=None, lhost=None, lport=None, rhost=None, rport=None, sessionid=None):
        if sessionid is not None or sessionid == -1:
            opts = {'TYPE': portfwdtype, 'LHOST': lhost, 'LPORT': lport, 'RHOST': rhost, 'RPORT': rport,
                    'SESSION': sessionid, 'CMD': 'delete'}
            result = MSFModule.run_msf_module_realtime(module_type="post", mname="multi/manage/portfwd_api", opts=opts,
                                                       timeout=RPC_SESSION_OPER_SHORT_REQ)
            if result is None:
                context = data_return(308, {}, PORTFWD_MSG_ZH.get(308), PORTFWD_MSG_EN.get(308))
                return context
            try:
                result_dict = json.loads(result)
            except Exception as E:
                logger.exception(E)
                logger.warning(result)
                context = data_return(302, [], PORTFWD_MSG_ZH.get(302), PORTFWD_MSG_EN.get(302))
                return context
            if result_dict.get('status') is True:
                Notice.send_info(f"删除端口转发 SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}",
                                 f"Delete portFwd SID:{sessionid} {portfwdtype} {lhost}/{lport} {rhost}/{rport}")
                context = data_return(204, result_dict.get('data'), PORTFWD_MSG_ZH.get(204), PORTFWD_MSG_EN.get(204))
                return context
            else:
                context = data_return(305, [], PORTFWD_MSG_ZH.get(305), PORTFWD_MSG_EN.get(305))
                return context
        else:
            context = data_return(306, [], PORTFWD_MSG_ZH.get(306), PORTFWD_MSG_EN.get(306))
            return context

    @staticmethod
    def _check_host_port(portfwd_type=None, lhost=None, lport=None, rhost=None, rport=None):
        if portfwd_type not in ['Reverse', 'Forward']:
            context = data_return(306, {}, PORTFWD_MSG_ZH.get(306), PORTFWD_MSG_EN.get(306))
            return False, context
        if lport is None or rport is None:
            context = data_return(306, {}, PORTFWD_MSG_ZH.get(306), PORTFWD_MSG_EN.get(306))
            return False, context
        if portfwd_type == "Reverse":
            if lhost is None:
                context = data_return(306, {}, PORTFWD_MSG_ZH.get(306), PORTFWD_MSG_EN.get(306))
                return False, context
        else:
            if rhost is None:
                context = data_return(306, {}, PORTFWD_MSG_ZH.get(306), PORTFWD_MSG_EN.get(306))
                return False, context
        return True, None
