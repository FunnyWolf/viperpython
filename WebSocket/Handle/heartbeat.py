# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
import functools
import ipaddress as ipaddr
import json
import time

from Core.Handle.host import Host
# from Lib.External.qqwry import qqwry
from Lib.configs import VIPER_IP
from Lib.ipgeo import IPGeo
from Lib.log import logger
from Lib.notice import Notice
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostLateral.Handle.edge import Edge
from PostModule.Handle.postmoduleauto import PostModuleAuto
from PostModule.Handle.postmoduleconfig import PostModuleConfig
from PostModule.Handle.postmoduleresulthistory import PostModuleResultHistory


class HeartBeat(object):
    def __init__(self):
        pass

    @staticmethod
    def first_heartbeat_result():
        hosts_sorted, network_data = HeartBeat.list_hostandsession()

        result_history = PostModuleResultHistory.list_all()

        Xcache.set_heartbeat_cache_result_history(result_history)

        notices = Notice.list_notices()

        jobs = Job.list_jobs()

        bot_wait_list = Job.list_bot_wait()

        # 任务队列长度
        task_queue_length = Xcache.get_module_task_length()
        module_options = PostModuleConfig.list_dynamic_option()
        result = {
            'hosts_sorted_update': True,
            'hosts_sorted': hosts_sorted,
            'network_data_update': True,
            'network_data': network_data,
            'result_history_update': True,
            'result_history': result_history,
            'notices_update': True,
            'notices': notices,
            'task_queue_length': task_queue_length,
            'jobs_update': True,
            'jobs': jobs,
            'bot_wait_list_update': True,
            'bot_wait_list': bot_wait_list,
            'module_options_update': True,
            'module_options': module_options,
        }

        return result

    @staticmethod
    def get_heartbeat_result():
        result = {}

        # jobs 列表 首先执行,刷新数据,删除过期任务
        jobs = Job.list_jobs()
        cache_jobs = Xcache.get_heartbeat_cache_jobs()
        if cache_jobs == jobs:
            result["jobs_update"] = False
            result["jobs"] = []
        else:
            Xcache.set_heartbeat_cache_jobs(jobs)
            result["jobs_update"] = True
            result["jobs"] = jobs

        # hosts_sorted,network_data
        hosts_sorted, network_data = HeartBeat.list_hostandsession()

        cache_hosts_sorted = Xcache.get_heartbeat_cache_hosts_sorted()
        if cache_hosts_sorted == hosts_sorted:
            result["hosts_sorted_update"] = False
            result["hosts_sorted"] = []
        else:
            Xcache.set_heartbeat_cache_hosts_sorted(hosts_sorted)
            result["hosts_sorted_update"] = True
            result["hosts_sorted"] = hosts_sorted

        cache_network_data = Xcache.get_heartbeat_cache_network_data()
        if cache_network_data == network_data:
            result["network_data_update"] = False
            result["network_data"] = {"nodes": [], "edges": []}
        else:
            Xcache.set_heartbeat_cache_network_data(network_data)
            result["network_data_update"] = True
            result["network_data"] = network_data

        # result_history
        result_history = PostModuleResultHistory.list_all()

        cache_result_history = Xcache.get_heartbeat_cache_result_history()

        if cache_result_history == result_history:
            result["result_history_update"] = False
            result["result_history"] = []
        else:
            Xcache.set_heartbeat_cache_result_history(result_history)
            result["result_history_update"] = True
            result["result_history"] = result_history

        # notices
        notices = Notice.list_notices()
        cache_notices = Xcache.get_heartbeat_cache_notices()
        if cache_notices == notices:
            result["notices_update"] = False
            result["notices"] = []
        else:
            Xcache.set_heartbeat_cache_notices(notices)
            result["notices_update"] = True
            result["notices"] = notices

        # 任务队列长度
        task_queue_length = Xcache.get_module_task_length()
        result["task_queue_length"] = task_queue_length

        # bot_wait_list 列表
        bot_wait_list = Job.list_bot_wait()
        cache_bot_wait_list = Xcache.get_heartbeat_cache_bot_wait_list()
        if cache_bot_wait_list == bot_wait_list:
            result["bot_wait_list_update"] = False
            result["bot_wait_list"] = []
        else:
            Xcache.set_heartbeat_cache_bot_wait_list(bot_wait_list)
            result["bot_wait_list_update"] = True
            result["bot_wait_list"] = bot_wait_list

        # module_options 列表
        module_options = PostModuleConfig.list_dynamic_option()
        cache_module_options = Xcache.get_heartbeat_cache_module_options()
        if cache_module_options == module_options:
            result["module_options_update"] = False
            result["module_options"] = []
        else:
            Xcache.set_heartbeat_cache_module_options(module_options)
            result["module_options_update"] = True
            result["module_options"] = module_options
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
        sessions = HeartBeat.list_sessions()

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
    def list_sessions():
        # 更新session的监听配置
        uuid_msfjobid = {}
        msfjobs = Job.list_msfrpc_jobs()
        if msfjobs is not None:
            for jobid in msfjobs:
                datastore = msfjobs[jobid].get("datastore")
                if datastore is not None:
                    uuid_msfjobid[msfjobs[jobid]["uuid"]] = {"job_id": int(jobid),
                                                             "PAYLOAD": datastore.get("PAYLOAD"),
                                                             "LPORT": datastore.get("LPORT"),
                                                             "LHOST": datastore.get("LHOST"),
                                                             "RHOST": datastore.get("RHOST")}
        else:
            if Xcache.msfrpc_heartbeat_error_send():
                Notice.send_warning(f"渗透服务心跳超时",
                                    "MSFRPC service heartbeat timeout")
                logger.warning(f'渗透服务心跳超时')
        sessions = []
        # session_info_dict = RpcClient.call(Method.SessionList, timeout=RPC_FRAMEWORK_API_REQ)
        session_info_dict = Xcache.get_msf_sessions_cache()

        if session_info_dict is None:
            return []

        if session_info_dict.get('error'):
            logger.warning(session_info_dict.get('error_string'))
            return []

        sessionhosts = []
        for session_id_str in session_info_dict.keys():
            session_info = session_info_dict.get(session_id_str)
            if session_info is not None:
                one_session = {}
                try:
                    one_session['id'] = int(session_id_str)
                except Exception as E:
                    logger.warning(E)
                    continue

                # 处理linux的no-user问题
                if str(session_info.get('info')).split(' @ ')[0] == "no-user":
                    session_info['info'] = session_info.get('info')[10:]

                # 处理session对应监听问题
                one_session['exploit_uuid'] = session_info.get('exploit_uuid')
                if uuid_msfjobid.get(session_info.get('exploit_uuid')) is None:
                    one_session['job_info'] = {"job_id": -1,
                                               "PAYLOAD": None,
                                               "LPORT": None,
                                               "LHOST": None,
                                               "RHOST": None}
                else:
                    one_session['job_info'] = uuid_msfjobid.get(session_info.get('exploit_uuid'))

                one_session['type'] = session_info.get('type')
                one_session['session_host'] = session_info.get('session_host')

                tunnel_local = session_info.get('tunnel_local').replace("::ffff:", "")
                one_session['tunnel_local'] = tunnel_local

                tunnel_peer = session_info.get('tunnel_peer').replace("::ffff:", "")
                one_session['tunnel_peer'] = tunnel_peer

                tunnel_peer_ip = tunnel_peer.split(":")[0]
                one_session['tunnel_peer_ip'] = tunnel_peer_ip

                one_session['tunnel_peer_locate_zh'] = IPGeo.get_ip_geo_str(tunnel_peer_ip, "zh-CN")
                one_session['tunnel_peer_locate_en'] = IPGeo.get_ip_geo_str(tunnel_peer_ip, "en-US")

                one_session['comm_channel_session'] = session_info.get('comm_channel_session')
                one_session['via_exploit'] = session_info.get('via_exploit')
                one_session['via_payload'] = session_info.get('via_payload')

                one_session['uuid'] = session_info.get('uuid')
                one_session['platform'] = session_info.get('platform')
                one_session['last_checkin'] = session_info.get('last_checkin') // 5 * 5
                one_session['fromnow'] = (int(time.time()) - session_info.get('last_checkin')) // 5 * 5
                one_session['info'] = session_info.get('info')
                one_session['arch'] = session_info.get('arch')

                try:
                    one_session['user'] = str(session_info.get('info')).split(' @ ')[0]
                    one_session['computer'] = str(session_info.get('info')).split(' @ ')[1]
                except Exception as _:
                    one_session['user'] = "Initializing"
                    one_session['computer'] = "Initializing"
                    one_session['advanced_info'] = {"sysinfo": {}, "username": "Initializing"}
                    one_session['os'] = None
                    one_session['load_powershell'] = False
                    one_session['load_python'] = False
                    one_session['routes'] = []
                    one_session['isadmin'] = False
                    one_session['available'] = False  # 是否初始化完成
                    sessions.append(one_session)
                    continue

                one_session['load_powershell'] = session_info.get('load_powershell')
                one_session['load_python'] = session_info.get('load_python')

                advanced_info = session_info.get('advanced_info')
                one_session['advanced_info'] = advanced_info

                try:
                    one_session['os'] = advanced_info.get("sysinfo").get("OS")
                    one_session['os_short'] = advanced_info.get("sysinfo").get("OS").split("(")[0]
                except Exception as _:
                    one_session['os'] = None
                    one_session['os_short'] = None

                try:
                    one_session['isadmin'] = advanced_info.get("sysinfo").get("IsAdmin")
                    if session_info.get('platform').lower().startswith('linux'):
                        if "uid=0" in one_session['info'].lower() or "root" in one_session['info'].lower():
                            one_session['isadmin'] = True
                except Exception as _:
                    one_session['isadmin'] = None

                try:
                    one_session['pid'] = advanced_info.get("sysinfo").get("Pid")
                except Exception as _:
                    one_session['pid'] = -1  # linux暂时不支持展示pid

                routestrlist = session_info.get('routes')
                one_session['routes'] = []
                try:
                    if isinstance(routestrlist, list):
                        for routestr in routestrlist:
                            routestr.split('/')
                            tmpdict = {"subnet": routestr.split('/')[0], 'netmask': routestr.split('/')[1]}
                            one_session['routes'].append(tmpdict)
                except Exception as E:
                    logger.error(E)
                one_session['available'] = True
                sessions.append(one_session)

                # session监控统计信息
                sessionhosts.append(session_info.get('session_host'))

        def session_host_key(item):
            try:
                ip = item.get("session_host")
                result = tuple(int(part) for part in ip.split('.'))
            except Exception as _:
                return 0, 0, 0, 0
            return result

        def session_cout_by_session_host(session, sessions):
            count = 0
            sesison_host = session.get("session_host")
            for tmp in sessions:
                if tmp.get("available"):
                    if tmp.get("session_host") == sesison_host:
                        count += 1
            return count

        sessions = sorted(sessions, key=session_host_key)

        # 获取新增的session配置信息
        add_session_dict = Xcache.update_session_list(sessions)
        # session监控功能
        if Xcache.get_sessionmonitor_conf().get("flag"):
            for session_uuid in add_session_dict:
                session = add_session_dict.get(session_uuid)
                sessionsms = f"ID:{session.get('id')}\t\n" \
                             f"Host:{session.get('session_host')}\t\n" \
                             f"Local:{session.get('tunnel_local')}\t\n" \
                             f"Peer:{session.get('tunnel_peer')}\t\n" \
                             f"Peer_ZH:{session.get('tunnel_peer_locate_zh')}\t\n" \
                             f"Peer_EN:{session.get('tunnel_peer_locate_en')}\t\n" \
                             f"Platform:{session.get('platform')}\t\n" \
                             f"Heartbeat:{session.get('fromnow')}\t\n" \
                             f"Info:{session.get('info')}\t\n" \
                             f"OS:{session.get('os')}\t\n" \
                             f"Arch:{session.get('arch')}\t\n"

                Notice.send_sms(f"新增session: {sessionsms}",
                                f"New session: {sessionsms}")

        # postmoduleauto功能
        if Xcache.get_postmodule_auto_conf().get("flag"):
            max_session = Xcache.get_postmodule_auto_conf().get("max_session")
            if max_session is None:
                max_session = 3
            if max_session < 3 or max_session > 5:
                max_session = 3

            for session_uuid in add_session_dict:
                if session_cout_by_session_host(add_session_dict.get(session_uuid), sessions) >= max_session:
                    continue

                PostModuleAuto.send_task(json.dumps(add_session_dict.get(session_uuid)))
                Notice.send_info(f"发送自动编排任务: SID {add_session_dict.get(session_uuid).get('id')}",
                                 f"Send automation tasks: SID {add_session_dict.get(session_uuid).get('id')}")

        return sessions
