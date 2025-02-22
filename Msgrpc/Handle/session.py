# -*- coding: utf-8 -*-
# @File  : session.py
# @Date  : 2021/2/25
# @Desc  :
import json
import time

from Lib.api import data_return
from Lib.configs import Session_MSG_ZH, CODE_MSG_ZH, RPC_SESSION_OPER_SHORT_REQ, CODE_MSG_EN, Session_MSG_EN, VIPER_IP
from Lib.ipgeo import IPGeo
from Lib.log import logger
from Lib.method import Method
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.sessionlib import SessionLib
from Lib.xcache import Xcache
from Msgrpc.Handle.job import Job
from Msgrpc.serializers import SessionLibSerializer
from PostModule.Handle.postmoduleauto import PostModuleAuto


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
                    one_session['session_host'] = VIPER_IP

                    sessions.append(one_session)
                    continue

                one_session['available'] = True
                one_session['session_host'] = session_info.get('session_host')

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
                    logger.exception(E)

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
                logger.exception(E)
                Notice.send_warning(f"{Session_MSG_ZH.get(301)} SID: {sessionid}",
                                    f"{Session_MSG_EN.get(301)} SID: {sessionid}")
                context = data_return(301, {}, Session_MSG_ZH.get(301), Session_MSG_EN.get(301))
                return context
