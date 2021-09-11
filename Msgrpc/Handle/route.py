# -*- coding: utf-8 -*-
# @File  : route.py
# @Date  : 2021/2/25
# @Desc  :
import json

from Lib.api import data_return
from Lib.configs import CODE_MSG, Route_MSG, RPC_FRAMEWORK_API_REQ, RPC_SESSION_OPER_SHORT_REQ
from Lib.log import logger
from Lib.method import Method
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.rpcclient import RpcClient


class Route(object):

    @staticmethod
    def get_match_route_for_ipaddress_list(ipaddress_list=None):
        if isinstance(ipaddress_list, list) is not True:
            return None
        if ipaddress_list is []:
            return []
        params = [ipaddress_list]
        result = RpcClient.call(Method.SessionMeterpreterRouteGet, params, timeout=RPC_FRAMEWORK_API_REQ)

        return result

    @staticmethod
    def list(sessionid=None):
        result = Route.list_route()

        if isinstance(result, list):
            if sessionid is not None or sessionid == -1:
                tmproutes = []
                for route in result:
                    if sessionid == route.get('session'):
                        tmproutes.append(route)

                context = data_return(200, {"route": tmproutes}, CODE_MSG.get(200))
                return context
            else:

                context = data_return(200, {"route": result}, CODE_MSG.get(200))
                return context
        else:
            logger.warning(result)
            context = data_return(306, {}, Route_MSG.get(306))
            return context

    @staticmethod
    def list_route():
        result = RpcClient.call(Method.SessionMeterpreterRouteList)
        if result is None:
            return []
        return result

    @staticmethod
    def create(subnet=None, netmask=None, sessionid=None, autoroute=None):
        if autoroute is True:
            # 调用autoroute
            opts = {'CMD': 'autoadd', 'SESSION': sessionid}
        else:
            opts = {'CMD': 'add', 'SUBNET': subnet, 'NETMASK': netmask, 'SESSION': sessionid}
        result = MSFModule.run(module_type="post", mname="multi/manage/routeapi", opts=opts,
                               timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result is None:
            context = data_return(505, [], CODE_MSG.get(505))
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.warning(E)
            context = data_return(306, [], Route_MSG.get(306))
            return context
        if result_dict.get('status') is True:
            if isinstance(result_dict.get('data'), list):
                if autoroute:
                    Notice.send_success(f"新增路由,SID:{sessionid} 自动模式", f"Create route success,SID:{sessionid} Auto")
                else:
                    Notice.send_success(f"新增路由,SID:{sessionid} {subnet}/{netmask}",
                                        f"Create route success,SID:{sessionid} {subnet}/{netmask}")

                context = data_return(201, result_dict.get('data'), Route_MSG.get(201))
            else:
                context = data_return(305, [], Route_MSG.get(305))
            return context
        else:
            context = data_return(305, [], Route_MSG.get(305))
            return context

    @staticmethod
    def destory(subnet=None, netmask=None, sessionid=None):
        opts = {'CMD': 'delete', 'SUBNET': subnet, 'NETMASK': netmask, 'SESSION': sessionid}
        result = MSFModule.run(module_type="post", mname="multi/manage/routeapi", opts=opts,
                               timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result is None:
            context = data_return(505, [], CODE_MSG.get(505))
            return context
        try:
            result_dict = json.loads(result)
        except Exception as E:
            logger.warning(E)
            context = data_return(306, {}, Route_MSG.get(306))
            return context

        if result_dict.get('status') is True:
            Notice.send_info(f"删除路由,SID:{sessionid} {subnet}/{netmask}",
                             f"Delete route,SID:{sessionid} {subnet}/{netmask}")
            context = data_return(204, {}, Route_MSG.get(204))
            return context
        else:
            context = data_return(304, {}, Route_MSG.get(304))
            return context
