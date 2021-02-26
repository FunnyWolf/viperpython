# -*- coding: utf-8 -*-
# @File  : hostandsession.py
# @Date  : 2021/2/25
# @Desc  :
import copy

from Core.Handle.host import Host
from Msgrpc.Handle.session import Session


class HostAndSession(object):
    def __init__(self):
        pass

    @staticmethod
    def list_hostandsession():
        hosts = Host.list_hosts()
        sessions = Session.list_sessions()

        # 初始化session列表
        for host in hosts:
            host['session'] = None

        hosts_with_session = []

        # 聚合Session和host
        host_exist = False
        for session in sessions:
            for host in hosts:
                if session.get("session_host") == host.get('ipaddress'):
                    temp_host = copy.deepcopy(host)
                    temp_host['session'] = session
                    hosts_with_session.append(temp_host)
                    host_exist = True
                    break

            if host_exist is True:
                host_exist = False
            else:
                if session.get("session_host") is None or session.get("session_host") == "":
                    host_exist = False
                else:
                    # 减少新建无效的host
                    if session.get("available"):
                        host_create = Host.create_host(session.get("session_host"))
                    else:
                        host_create = Host.create_host("255.255.255.255")
                    host_create['session'] = session
                    hosts_with_session.append(host_create)
                    host_exist = False

        for host in hosts:
            add = True
            for temp_host in hosts_with_session:
                if temp_host.get("id") == host.get("id"):
                    add = False
                    break
            if add:
                hosts_with_session.append(host)

        # 设置host的proxy信息
        # 收集所有hostip
        ipaddress_list = []
        for host in hosts_with_session:
            ipaddress_list.append(host.get('ipaddress'))

        i = 0
        for one in hosts_with_session:
            one["order_id"] = i
            i += 1

        return hosts_with_session
