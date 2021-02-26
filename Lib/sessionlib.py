# -*- coding: utf-8 -*-
# @File  : sessionlib.py
# @Date  : 2021/2/26
# @Desc  :
import json
import time

from Lib.External.geoip import Geoip
from Lib.log import logger
from Lib.method import Method
from Lib.msfmodule import MSFModule
from Lib.notice import Notice
from Lib.rpcclient import RpcClient
from Lib.xcache import Xcache


class SessionLib(object):
    """收集session的基本信息,用于Session和postmodule的lib"""
    SID_TO_INTEGERITY_LEVEL = {
        'S-1-16-4096': 'low',
        'S-1-16-8192': 'medium',
        'S-1-16-12288': 'high',
        'S-1-16-16384': 'system'
    }
    UAC_NO_PROMPT = 0
    UAC_PROMPT_CREDS_IF_SECURE_DESKTOP = 1
    UAC_PROMPT_CONSENT_IF_SECURE_DESKTOP = 2
    UAC_PROMPT_CREDS = 3
    UAC_PROMPT_CONSENT = 4
    UAC_DEFAULT = 5

    def __init__(self, sessionid=None, rightinfo=False, uacinfo=False, pinfo=False):
        self._rightinfo = rightinfo  # uac开关,uac登记 TEMP目录
        self._uacinfo = uacinfo  # 管理员组 完整性
        self._pinfo = pinfo  # 进程相关嘻嘻
        self.sessionid = sessionid
        self._session_uuid = None
        self.update_time = 0

        # RIGHTINFO
        self.is_in_admin_group = None
        self.is_admin = None
        self.tmpdir = None

        # UACINFO
        self.is_uac_enable = None
        self.uac_level = -1
        self.integrity = None

        # PINFO
        self.pid = -1
        self.pname = None
        self.ppath = None
        self.puser = None
        self.parch = None
        self.processes = []

        # 基本信息
        self.load_powershell = False
        self.load_python = False
        self.domain = None
        self.session_host = None
        self.type = None
        self.computer = None
        self.arch = None
        self.platform = None
        self.last_checkin = 0
        self.user = None
        self.os = None
        self.os_short = None
        self.logged_on_users = 0
        self.tunnel_local = None
        self.tunnel_peer = None
        self.tunnel_peer_ip = None
        self.tunnel_peer_locate = None
        self.tunnel_peer_asn = None
        self.via_exploit = None
        self.via_payload = None
        self.route = []
        self._init_info()

    def _init_info(self):
        """初始化session信息"""
        # 更新基本信息
        self._set_base_info()
        # 是否需要拓展的信息
        if self._rightinfo or self._pinfo or self._uacinfo:
            cache_result = Xcache.get_session_info(self.sessionid)
            if cache_result is None:
                module_type = "post"
                mname = "multi/gather/session_info"
                opts = {'SESSION': self.sessionid, 'PINFO': self._pinfo, 'RIGHTINFO': self._rightinfo,
                        'UACINFO': self._uacinfo}
                result = MSFModule.run(module_type=module_type, mname=mname, opts=opts, timeout=30)
            else:
                result = cache_result
            if result is None:
                Notice.send_warning("更新Session信息,请稍后重试".format(result))
                return
            try:
                result_dict = json.loads(result)
                self._set_advanced_info(result_dict)
                if self._rightinfo and self._pinfo and self._uacinfo:
                    result_dict["update_time"] = int(time.time())
                    Xcache.set_session_info(self.sessionid, json.dumps(result_dict))
            except Exception as E:
                logger.warning(E)
                logger.warning("更新Session信息失败,返回消息为{}".format(result))
                Notice.send_warning("更新Session信息失败,请稍后重试".format(result))

    def get_session(self):
        info = RpcClient.call(Method.SessionGet, [self.sessionid], timeout=3)
        if info is not None:

            one_session = {'id': self.sessionid}
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
                one_session['os_short'] = None
                one_session['load_powershell'] = False
                one_session['load_python'] = False
                one_session['uuid'] = info.get('uuid')
                one_session['routes'] = []
                one_session['isadmin'] = False
                one_session['available'] = False  # 是否初始化完成
                return one_session
            else:
                one_session['type'] = info.get('type')
                one_session['session_host'] = info.get('session_host')
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
                return one_session
        else:
            return None

    def _set_base_info(self):
        one = self.get_session()
        if one is None:
            return False
        try:
            self.session_host = one.get('session_host')
            self.type = one.get('type')
            self.tunnel_local = one.get('tunnel_local')
            self.tunnel_peer = one.get('tunnel_peer')
            # 解析信息
            self.tunnel_peer_ip = one.get('tunnel_peer').split(":")[0]
            self.tunnel_peer_locate = Geoip.get_city(one.get('tunnel_peer').split(":")[0])
            self.tunnel_peer_asn = Geoip.get_asn(one.get('tunnel_peer').split(":")[0])

            self.via_exploit = one.get('via_exploit')
            self.via_payload = one.get('via_payload')
            self.last_checkin = one.get('last_checkin')
            self.fromnow = int(time.time()) - one.get('last_checkin')
            self.is_admin = one.get('isadmin')
            self.load_powershell = one.get('load_powershell')
            self.load_python = one.get('load_python')
            self.domain = one.get('advanced_info').get("sysinfo").get("Domain")
            self.os = one.get('advanced_info').get("sysinfo").get("OS")

            try:
                self.os_short = one.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                if len(self.os_short) > 18:
                    self.os_short = f"{self.os_short[0:6]} ... {self.os_short[-6:]}"
            except Exception as _:
                self.os_short = None

            self.logged_on_users = one.get('advanced_info').get("sysinfo").get("Logged On Users")
            self.computer = one.get('computer')
            self.arch = one.get('arch')
            self.platform = one.get('platform')
            self.user = one.get('user')
            self._session_uuid = one.get('uuid')
        except Exception as E:
            logger.warning(E)

    def _set_advanced_info(self, result_dict=None):
        try:
            if result_dict.get('status'):
                self.is_in_admin_group = result_dict.get('data').get('IS_IN_ADMIN_GROUP')
                # self.is_admin = result_dict.get('data').get('IS_ADMIN')
                self.tmpdir = result_dict.get('data').get('TEMP')
                self.is_uac_enable = result_dict.get('data').get('IS_UAC_ENABLE')
                self.uac_level = result_dict.get('data').get('UAC_LEVEL')
                if self.uac_level is None:
                    self.uac_level = -1
                self.integrity = self.SID_TO_INTEGERITY_LEVEL.get(result_dict.get('data').get('INTEGRITY'))
                self.pid = result_dict.get('data').get('PID')
                self.pname = result_dict.get('data').get('PNAME')
                self.ppath = result_dict.get('data').get('PPATH')
                self.puser = result_dict.get('data').get('PUSER')
                self.parch = result_dict.get('data').get('PARCH')
                self.processes = result_dict.get('data').get('PROCESSES')
                self.update_time = result_dict.get('update_time')
            else:
                logger.warning("模块执行错误")
        except Exception as E:
            logger.warning(E)

    @property
    def is_alive(self):
        """session是否可用"""
        if int(time.time()) - self.last_checkin > 60 and self.user is None:
            return False
        else:
            return True

    @property
    def is_system(self):
        """session是否可用"""
        if self.user == 'NT AUTHORITY\\SYSTEM' or self.user == "root":
            return True
        else:
            return False

    @property
    def is_in_domain(self):
        if self.platform == "windows":
            if self.user is not None:
                try:
                    session_domain = self.user.split('\\')[0]
                    if session_domain.lower() == self.domain.lower():
                        return True
                    if session_domain.lower() == self.computer.lower():
                        return False
                    if session_domain.lower() == "nt authority":  # system权限默认在域中
                        return True
                    return False
                except Exception as E:
                    logger.warning(E)
                    return False
        else:
            return False

    @property
    def is_windows(self):
        if self.platform is None:
            return False
        elif self.platform.lower().startswith('window'):
            return True
        else:
            return False

    @property
    def is_linux(self):
        if self.platform is None:
            return False
        elif self.platform.lower().startswith('linux'):
            return True
        else:
            return False
