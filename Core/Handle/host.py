# -*- coding: utf-8 -*-
# @File  : hostinfo.py
# @Date  : 2021/2/25
# @Desc  :
import functools
import ipaddress as ipaddr

from Core.models import HostModel
from Core.serializers import HostSerializer
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, Host_MSG_ZH, Host_MSG_EN, CODE_MSG_EN, VIPER_IP
from Lib.log import logger
from Lib.xcache import Xcache
from Msgrpc.Handle.portfwd import PortFwd
from Msgrpc.Handle.route import Route
from Msgrpc.Handle.session import Session
from Msgrpc.Handle.socks import Socks
from PostLateral.Handle.edge import Edge
from PostLateral.Handle.intranetportservice import IntranetPortService
from PostLateral.models import IntranetPortServiceModel, VulnerabilityModel, EdgeModel


class Host(object):
    REGISTER_DESTORY = [IntranetPortServiceModel, VulnerabilityModel]  # 删除Host时同时删除列表中的数据

    def __init__(self):
        pass

    @staticmethod
    def list():
        """获取msfsocks页面所有信息"""
        hosts = Host.list_hosts()
        route_list = Route.list_route()
        socks_list = Socks.list_msf_socks()
        portfwd_list = PortFwd.list_portfwd()
        for host in hosts:
            ipaddress = host.get('ipaddress')
            # 端口信息
            host['portService'] = IntranetPortService.list_by_ipaddress(ipaddress)
            # 路由信息
            for route in route_list:
                ipnetwork = ipaddr.ip_network(f"{route.get('subnet')}/{route.get('netmask')}", strict=False)
                if ipaddr.ip_address(ipaddress) in ipnetwork:
                    host['route'] = {'type': 'ROUTE', 'data': route.get("session")}
                    break
            else:
                host['route'] = {'type': 'DIRECT', 'data': None}

        result = {'hosts': hosts, 'routes': route_list, 'socks': socks_list, 'portfwds': portfwd_list, }

        context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
        return context

    @staticmethod
    def list_hosts_with_route_and_portservice():
        """获取msfsocks页面所有信息"""
        hosts = Host.list_hosts()
        route_list = Route.list_route()
        for host in hosts:
            ipaddress = host.get('ipaddress')
            # 端口信息
            host['portService'] = IntranetPortService.list_by_ipaddress(ipaddress)
            # 路由信息
            for route in route_list:
                ipnetwork = ipaddr.ip_network(f"{route.get('subnet')}/{route.get('netmask')}", strict=False)
                if ipaddr.ip_address(ipaddress) in ipnetwork:
                    host['route'] = {'type': 'ROUTE', 'data': route.get("session")}
                    break
            else:
                host['route'] = {'type': 'DIRECT', 'data': None}
        return hosts

    @staticmethod
    def list_hosts():
        if HostModel.objects.filter(ipaddress=VIPER_IP).exists() is not True:
            HostModel.objects.create(ipaddress=VIPER_IP)
        models = HostModel.objects.all()

        result = HostSerializer(models, many=True).data
        return result

    @staticmethod
    def list_hostandsession():
        def short_payload(payload):
            payload = payload.replace("windows", "win")
            payload = payload.replace("linux", "lin")
            payload = payload.replace("meterpreter", "met")

            return payload

        def filter_session_by_ipaddress(ipaddress, sessions):
            result = []
            for session in sessions:
                if session.get("available"):
                    if session.get("session_host") == ipaddress:
                        result.append(session)

            return result

        def add_session_to_255(hosts, session):
            for host in hosts:
                if host.get('ipaddress') == VIPER_IP:
                    host["session"].append(session)

        hosts = Host.list_hosts()
        sessions = Session.list_sessions()

        # 初始化session列表
        for host in hosts:
            host['session'] = []

        # 聚合Session和host
        for session in sessions:
            session_host = session.get("session_host")
            if session_host is None or session_host == "":
                session_host = VIPER_IP  # 未知的session_host,默认为viper的ip (shell session和未初始化的session)

            # 确保每个session成功后都会添加edge
            if session.get("available"):
                payload = "/".join(session.get("via_payload").split("/")[1:])
                if "reverse" in payload:
                    source = session_host
                    target = VIPER_IP
                else:
                    source = VIPER_IP
                    target = session_host

                Edge.create_edge(source=source,
                                 target=target,
                                 type="online",
                                 data={"payload": payload})

            for host in hosts:
                if session_host == host.get('ipaddress'):
                    host['session'].append(session)
                    break
            else:
                # 未找到对应的host
                # 减少新建无效的host
                if session.get("available"):
                    host_create = Host.create_host(session_host)
                    host_create['session'] = [session]
                    hosts.append(host_create)
                else:
                    add_session_to_255(hosts, session)

        # 设置host的proxy信息
        # 收集所有hostip
        ipaddress_list = []
        for host in hosts:
            ipaddress_list.append(host.get('ipaddress'))

        def sort_host(a, b):
            if len(a['session']) < len(b['session']):
                return 1
            elif len(a['session']) > len(b['session']):
                return -1
            else:
                ch3 = lambda x: sum([256 ** j * int(i) for j, i in enumerate(x.split('.')[::-1])])
                try:
                    aipn = ch3(a["ipaddress"])
                except Exception as _:
                    aipn = 0
                try:
                    bipn = ch3(b["ipaddress"])
                except Exception as _:
                    bipn = 0

                if aipn > bipn:
                    return 1
                elif aipn < bipn:
                    return -1
            return 0

        # 根据时间排序
        hosts = sorted(hosts, key=functools.cmp_to_key(sort_host))

        i = 0
        for one in hosts:
            one["order_id"] = i
            i += 1

        # 开始处理network数据
        # 在这里处理是因为已经将session和host信息查找出来,直接使用即可
        # 获取nodes数据
        nodes = [
            {
                "id": VIPER_IP,
                "data": {
                    "type": 'viper',
                },
            },
        ]
        edges = []

        # 添加scan类型的edge
        online_edge_list = Edge.list_edge(type="scan")
        for online_edge in online_edge_list:
            edge_data = {
                "source": online_edge.get("source"),
                "target": online_edge.get("target"),
                "data": {
                    "type": 'scan',
                    "method": online_edge.get("data").get("method"),
                },
            }
            if edge_data not in edges:
                edges.append(edge_data)

        for host in hosts:
            ipaddress = host.get("ipaddress")
            if ipaddress == VIPER_IP:
                continue
            filter_sessions = filter_session_by_ipaddress(ipaddress, sessions)

            # host存在session
            if filter_sessions:
                # 加入 "包含session的主机节点"
                nodes.append({
                    "id": ipaddress,
                    "data": {
                        "type": 'host',
                        "sessionnum": len(filter_sessions),
                        "platform": filter_sessions[0].get("platform"),
                    },
                })
                for session in filter_sessions:
                    sid = session.get("id")
                    platform = session.get("platform")
                    payload = "/".join(session.get("via_payload").split("/")[1:])
                    comm_channel_session = session.get("comm_channel_session")

                    # 加入session节点
                    sesison_node_id = f"SID - {sid}"

                    nodes.append({
                        "id": sesison_node_id,
                        "data": {
                            "type": 'session',
                            "sid": sid,
                            "platform": platform,
                        },
                    })

                    # 主机节点连接到session节点
                    if "reverse" in payload:
                        source = sesison_node_id
                        target = ipaddress
                    else:
                        source = ipaddress
                        target = sesison_node_id

                    edge_data = {
                        "source": source,
                        "target": target,
                        "data": {
                            "type": 'session',
                            "payload": short_payload(payload),
                        },
                    }
                    if edge_data not in edges:
                        edges.append(edge_data)

                    if comm_channel_session is None:
                        # 主机节点连接到viper节点
                        if "reverse" in payload:
                            source = ipaddress
                            target = VIPER_IP
                        else:
                            source = VIPER_IP
                            target = ipaddress

                        edge = {
                            "source": source,
                            "target": target,
                            "data": {
                                "type": 'session',
                                "payload": short_payload(payload),
                            },
                        }
                        if edge not in edges:
                            edges.append(edge)
                    else:
                        # 查看是否存在online类型的edge
                        online_edge_list = Edge.list_edge(target=ipaddress, type="online")
                        online_edge_list.extend(Edge.list_edge(source=ipaddress, type="online"))
                        for online_edge in online_edge_list:
                            edge_data = {
                                "source": online_edge.get("source"),
                                "target": online_edge.get("target"),
                                "data": {
                                    "type": 'online',
                                    "payload": short_payload(online_edge.get("data").get("payload")),
                                },
                            }
                            if edge_data not in edges:
                                edges.append(edge_data)
                                break  # 不存在session的主机只取一个payload即可

                        # comm_channel_session 类型边
                        source_sesison_node_id = f"SID - {comm_channel_session}"

                        if "reverse" in payload:
                            source = sesison_node_id
                            target = source_sesison_node_id
                        else:
                            source = source_sesison_node_id
                            target = sesison_node_id

                        edge = {
                            "source": source,
                            "target": target,
                            "data": {
                                "type": 'comm',
                                "payload": short_payload(payload),
                                "sessionid": comm_channel_session,
                            },
                        }
                        if edge not in edges:
                            edges.append(edge)

                    # route edge
                    routes = session.get("routes")
                    sid = session.get("id")
                    for route in routes:
                        ipnetwork = ipaddr.ip_network(f"{route.get('subnet')}/{route.get('netmask')}", strict=False)
                        for host_in in hosts:
                            ipaddress_in = host_in.get("ipaddress")
                            if ipaddress_in == VIPER_IP or ipaddress_in == ipaddress:
                                continue
                            if ipaddr.ip_address(ipaddress_in) in ipnetwork:
                                edge_data = {
                                    "source": sesison_node_id,
                                    "target": ipaddress_in,
                                    "data": {
                                        "type": "route",
                                        "sid": sid,
                                    },
                                }
                                if edge_data not in edges:
                                    edges.append(edge_data)

            else:
                # host不存在session
                nodes.append({
                    "id": ipaddress,
                    "data": {
                        "type": 'host',
                    },
                })

                # 查看是否存在online类型的edge
                online_edge_list = Edge.list_edge(target=ipaddress, type="online")
                online_edge_list.extend(Edge.list_edge(source=ipaddress, type="online"))
                for online_edge in online_edge_list:
                    edge_data = {
                        "source": online_edge.get("source"),
                        "target": online_edge.get("target"),
                        "data": {
                            "type": 'online',
                            "payload": short_payload(online_edge.get("data").get("payload")),
                        },
                    }
                    if edge_data not in edges:
                        edges.append(edge_data)
                        break  # 不存在session的主机只取一个payload即可

        network_data = {"nodes": nodes, "edges": edges}
        return hosts, network_data

    @staticmethod
    def create_host(ipaddress, source=None, linktype=None, data=None):
        if data is None:
            data = {}
        # 新建edge信息
        if source is not None:
            Edge.create_edge(source=source, target=ipaddress, type=linktype, data=data)

        # 没有主机数据时新建
        defaultdict = {'ipaddress': ipaddress, }
        try:
            model, created = HostModel.objects.get_or_create(ipaddress=ipaddress, defaults=defaultdict)
        except Exception as E:
            # ip地址重复,清理旧数据并新建新主机
            HostModel.objects.filter(ipaddress=ipaddress).delete()
            model = HostModel.objects.create(ipaddress=ipaddress)
        result = HostSerializer(model, many=False).data
        return result

    @staticmethod
    def update(ipaddress=None, tag=None, comment=None):
        """更新主机标签,说明"""
        host_update = Host.update_host(ipaddress, tag, comment)
        if host_update is None:
            context = data_return(304, host_update, Host_MSG_ZH.get(304), Host_MSG_EN.get(304))
        else:
            context = data_return(201, host_update, Host_MSG_ZH.get(201), Host_MSG_EN.get(201))
        return context

    @staticmethod
    def update_host(ipaddress=None, tag=None, comment=None):
        # 没有此主机数据时新建
        defaultdict = {'ipaddress': ipaddress, 'tag': tag, 'comment': comment}
        try:
            model, created = HostModel.objects.update_or_create(ipaddress=ipaddress, defaults=defaultdict)
        except Exception as E:
            # ip地址重复,清理旧数据并新建新主机
            HostModel.objects.filter(ipaddress=ipaddress).delete()
            model = HostModel.objects.create(defaultdict)
        result = HostSerializer(model, many=False).data
        return result

    @staticmethod
    def destory_single(ipaddress=None):
        flag = Host.destory_host(ipaddress)
        if flag:
            context = data_return(202, {}, Host_MSG_ZH.get(202), Host_MSG_EN.get(202))
        else:
            context = data_return(301, {}, Host_MSG_ZH.get(301), Host_MSG_EN.get(301))
        return context

    @staticmethod
    def destory_mulit(ipaddress_list):
        for ipaddress in ipaddress_list:
            Host.destory_host(ipaddress)

        context = data_return(202, {}, Host_MSG_ZH.get(202), Host_MSG_EN.get(202))
        return context

    @staticmethod
    def destory_host(ipaddress=None):
        # 删除相关缓存信息
        # 255.255.255.255 特殊处理
        if ipaddress == VIPER_IP:
            return False

        # 删除缓存的session命令行结果
        Xcache.del_sessionio_cache(ipaddress=ipaddress)
        # 删除缓存的模块结果
        Xcache.del_module_result_by_ipaddress(ipaddress=ipaddress)
        # 删除缓存的模块历史结果
        Xcache.del_module_result_history_by_ipaddress(ipaddress=ipaddress)

        try:
            # 删除主表信息
            HostModel.objects.filter(ipaddress=ipaddress).delete()
            # 删除关联表信息
            for OneModel in Host.REGISTER_DESTORY:
                OneModel.objects.filter(ipaddress=ipaddress).delete()
            # 删除edge表信息
            EdgeModel.objects.filter(source=ipaddress).delete()
            EdgeModel.objects.filter(target=ipaddress).delete()

            # 删除host_info信息
            Xcache.del_host_info(ipaddress)

            return True
        except Exception as E:
            logger.exception(E)
            return False
