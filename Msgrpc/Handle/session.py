# -*- coding: utf-8 -*-
# @File  : session.py
# @Date  : 2021/2/25
# @Desc  :
import time

from Lib.External.geoip import Geoip
from Lib.api import data_return
from Lib.configs import Session_MSG, CODE_MSG
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
            context = data_return(304, Session_MSG.get(304), {})
            return context
        session_interface = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_interface).data
        context = data_return(200, CODE_MSG.get(200), result)
        return context

    @staticmethod
    def update(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, Session_MSG.get(304), {})
            return context
        Xcache.set_session_info(sessionid, None)
        session_lib = SessionLib(sessionid, rightinfo=True, uacinfo=True, pinfo=True)
        result = SessionLibSerializer(session_lib).data
        context = data_return(203, Session_MSG.get(203), result)
        return context

    @staticmethod
    def destroy(sessionid=None):
        if sessionid is None or sessionid <= 0:
            context = data_return(304, Session_MSG.get(304), {})
            return context
        else:
            params = [sessionid]
            try:
                result = RpcClient.call(Method.SessionStop, params, timeout=12)
                if result is None:  # 删除超时
                    Notice.send_success(f"{Session_MSG.get(202)} SID: {sessionid}")
                    context = data_return(202, Session_MSG.get(202), {})
                    return context
                elif result.get('result') == 'success':
                    Notice.send_success(f"{Session_MSG.get(201)} SID: {sessionid}")
                    context = data_return(201, Session_MSG.get(201), {})
                    return context
                else:
                    Notice.send_warning(f"{Session_MSG.get(301)} SID: {sessionid}")
                    context = data_return(301, Session_MSG.get(301), {})
                    return context
            except Exception as E:
                logger.error(E)
                Notice.send_warning(f"{Session_MSG.get(301)} SID: {sessionid}")
                context = data_return(301, Session_MSG.get(301), {})
                return context

    @staticmethod
    def list_sessions():
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

                try:
                    one_session['user'] = str(info.get('info')).split(' @ ')[0]
                    one_session['computer'] = str(info.get('info')).split(' @ ')[1]
                except Exception as _:
                    one_session['user'] = "Initializing"
                    one_session['computer'] = "Initializing"
                    one_session['type'] = info.get('type')
                    one_session['session_host'] = info.get('session_host')
                    sessionhosts.append(info.get('session_host'))
                    one_session['tunnel_local'] = info.get('tunnel_local')
                    one_session['tunnel_peer'] = info.get('tunnel_peer')
                    one_session['via_exploit'] = info.get('via_exploit')
                    one_session['via_payload'] = info.get('via_payload')
                    one_session['info'] = info.get('info')
                    one_session['arch'] = info.get('arch')
                    one_session['platform'] = info.get('platform')
                    one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                    one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                    one_session['advanced_info'] = {"sysinfo": {}, "username": "Initializing"}
                    one_session['os'] = None
                    one_session['load_powershell'] = False
                    one_session['load_python'] = False
                    one_session['uuid'] = info.get('uuid')
                    one_session['routes'] = []
                    one_session['isadmin'] = False
                    one_session['available'] = False  # 是否初始化完成
                    sessions.append(one_session)
                    continue
                one_session['type'] = info.get('type')
                one_session['session_host'] = info.get('session_host')
                sessionhosts.append(info.get('session_host'))
                one_session['tunnel_local'] = info.get('tunnel_local')
                one_session['tunnel_peer'] = info.get('tunnel_peer')
                one_session['tunnel_peer_ip'] = info.get('tunnel_peer').split(":")[0]
                one_session['tunnel_peer_locate'] = Geoip.get_city(info.get('tunnel_peer').split(":")[0])
                one_session['via_exploit'] = info.get('via_exploit')
                one_session['via_payload'] = info.get('via_payload')
                one_session['info'] = info.get('info')
                one_session['arch'] = info.get('arch')
                one_session['platform'] = info.get('platform')
                one_session['last_checkin'] = info.get('last_checkin') // 10 * 10
                one_session['fromnow'] = (int(time.time()) - info.get('last_checkin')) // 10 * 10
                one_session['advanced_info'] = info.get('advanced_info')
                try:
                    one_session['os'] = info.get('advanced_info').get("sysinfo").get("OS")
                    one_session['os_short'] = info.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                except Exception as _:
                    one_session['os'] = None
                    one_session['os_short'] = None
                one_session['load_powershell'] = info.get('load_powershell')
                one_session['load_python'] = info.get('load_python')
                one_session['uuid'] = info.get('uuid')
                try:
                    one_session['isadmin'] = info.get('advanced_info').get("sysinfo").get("IsAdmin")

                    if info.get('platform').lower().startswith('linux'):
                        if "uid=0" in one_session['info'].lower():
                            one_session['isadmin'] = True
                except Exception as _:
                    one_session['isadmin'] = None

                routestrlist = info.get('routes')

                try:
                    one_session['routes'] = []
                    if isinstance(routestrlist, list):
                        for routestr in routestrlist:
                            routestr.split('/')
                            tmpdict = {"subnet": routestr.split('/')[0], 'netmask': routestr.split('/')[1]}
                            one_session['routes'].append(tmpdict)
                except Exception as E:
                    logger.error(E)
                one_session['available'] = True
                sessions_available_count += 1
                sessions.append(one_session)

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

    @staticmethod
    def destroy_session(session_id=None):
        if session_id is None:
            return False
        else:
            params = [session_id]
            try:
                result = RpcClient.call(Method.SessionStop, params)
                if result is None:
                    return False
                if result.get('result') == 'success':
                    return True
                else:
                    return False
            except Exception as E:
                logger.error(E)
                return False
