# -*- coding: utf-8 -*-
# @File  : heartbeat.py
# @Date  : 2021/2/27
# @Desc  :
import copy
import time

from Core.Handle.host import Host
from Lib.External.geoip import Geoip
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from PostModule.Handle.postmoduleresulthistory import PostModuleResultHistory


class HeartBeat(object):
    def __init__(self):
        pass

    @staticmethod
    def first_heartbeat_result():
        hosts_sorted = HeartBeat.list_hostandsession()

        result_history = PostModuleResultHistory.list_all()
        for one in result_history:
            for host in hosts_sorted:
                if one.get("hid") == host.get("id"):
                    one["ipaddress"] = host.get("ipaddress")
                    break
        Xcache.set_heartbeat_cache_result_history(result_history)

        notices = Notice.list_notices()

        jobs = Job.list_jobs()

        bot_wait_list = Job.list_bot_wait()

        # 任务队列长度
        task_queue_length = Xcache.get_module_task_length()

        result = {
            'hosts_sorted_update': True,
            'hosts_sorted': hosts_sorted,
            'result_history_update': True,
            'result_history': result_history,
            'notices_update': True,
            'notices': notices,
            'task_queue_length': task_queue_length,
            'jobs_update': True,
            'jobs': jobs,
            'bot_wait_list_update': True,
            'bot_wait_list': bot_wait_list
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

        # hosts_sorted
        hosts_sorted = HeartBeat.list_hostandsession()
        cache_hosts_sorted = Xcache.get_heartbeat_cache_hosts_sorted()
        if cache_hosts_sorted == hosts_sorted:
            result["hosts_sorted_update"] = False
            result["hosts_sorted"] = []
        else:
            Xcache.set_heartbeat_cache_hosts_sorted(hosts_sorted)
            result["hosts_sorted_update"] = True
            result["hosts_sorted"] = hosts_sorted

        # result_history
        result_history = PostModuleResultHistory.list_all()
        for one in result_history:
            for host in hosts_sorted:
                if one.get("hid") == host.get("id"):
                    one["ipaddress"] = host.get("ipaddress")
                    break

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

        return result

    @staticmethod
    def list_hostandsession():
        hosts = Host.list_hosts()
        sessions = HeartBeat.list_sessions()

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

    @staticmethod
    def list_sessions():
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

        sessions_available_count = 0
        sessions = []
        infos = RpcClient.call(Method.SessionList, timeout=3)
        if infos is None:
            return sessions

        if infos.get('error'):
            logger.warning(infos.get('error_string'))
            return sessions
        sessionhosts = []
        for key in infos.keys():
            info = infos.get(key)
            if info is not None:
                one_session = {}
                try:
                    one_session['id'] = int(key)
                except Exception as E:
                    logger.warning(E)
                    continue

                # 处理linux的no-user问题
                if str(info.get('info')).split(' @ ')[0] == "no-user":
                    info['info'] = info.get('info')[10:]

                one_session['type'] = info.get('type')
                one_session['session_host'] = info.get('session_host')
                one_session['tunnel_local'] = info.get('tunnel_local')
                one_session['tunnel_peer'] = info.get('tunnel_peer')
                one_session['tunnel_peer_ip'] = info.get('tunnel_peer').split(":")[0]
                one_session['tunnel_peer_locate'] = Geoip.get_city(info.get('tunnel_peer').split(":")[0])
                one_session['via_exploit'] = info.get('via_exploit')
                one_session['exploit_uuid'] = info.get('exploit_uuid')

                if uuid_msfjobid.get(info.get('exploit_uuid')) is None:
                    one_session['job_info'] = {"job_id": -1,
                                               "PAYLOAD": None,
                                               "LPORT": None,
                                               "LHOST": None,
                                               "RHOST": None}
                else:
                    one_session['job_info'] = uuid_msfjobid.get(info.get('exploit_uuid'))

                one_session['via_payload'] = info.get('via_payload')
                one_session['tunnel_peer_ip'] = info.get('tunnel_peer').split(":")[0]
                one_session['tunnel_peer_locate'] = Geoip.get_city(info.get('tunnel_peer').split(":")[0])
                one_session['uuid'] = info.get('uuid')
                one_session['platform'] = info.get('platform')
                one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                one_session['info'] = info.get('info')
                one_session['arch'] = info.get('arch')
                try:
                    one_session['user'] = str(info.get('info')).split(' @ ')[0]
                    one_session['computer'] = str(info.get('info')).split(' @ ')[1]
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

                one_session['load_powershell'] = info.get('load_powershell')
                one_session['load_python'] = info.get('load_python')

                one_session['advanced_info'] = info.get('advanced_info')
                try:
                    one_session['os'] = info.get('advanced_info').get("sysinfo").get("OS")
                    one_session['os_short'] = info.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                except Exception as _:
                    one_session['os'] = None
                    one_session['os_short'] = None
                try:
                    one_session['isadmin'] = info.get('advanced_info').get("sysinfo").get("IsAdmin")
                    if info.get('platform').lower().startswith('linux'):
                        if "uid=0" in one_session['info'].lower():
                            one_session['isadmin'] = True
                except Exception as _:
                    one_session['isadmin'] = None

                routestrlist = info.get('routes')
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
                sessionhosts.append(info.get('session_host'))
                sessions_available_count += 1

        def split_ip(ip):
            try:
                result = tuple(int(part) for part in ip.split('.'))
            except Exception as E:
                logger.exception(E)
                return 0, 0, 0
            return result

        def session_host_key(item):
            return split_ip(item.get("session_host"))

        sessions = sorted(sessions, key=session_host_key)

        # session监控功能
        if Xcache.get_sessionmonitor_conf().get("flag"):
            if Xcache.get_session_count() < sessions_available_count:
                Notice.send_sms(f"当前Session数量: {sessions_available_count} IP列表: {','.join(sessionhosts)}")
                Notice.send_info(f"当前Session数量: {sessions_available_count}")
            if Xcache.get_session_count() != sessions_available_count:
                Xcache.set_session_count(sessions_available_count)
        return sessions
