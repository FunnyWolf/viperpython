# -*- coding: utf-8 -*-
# @File  : sessionlib.py
# @Date  : 2021/2/26
# @Desc  :
import json
import time

from Lib.configs import RPC_FRAMEWORK_API_REQ, RPC_SESSION_OPER_SHORT_REQ, RPC_SESSION_OPER_LONG_REQ
from Lib.ipgeo import IPGeo
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

    def __init__(self, sessionid=None, rightinfo=False, uacinfo=False, pinfo=False):
        self.sessionid = sessionid
        self._rightinfo = rightinfo  # uac开关,uac登记 TEMP目录
        self._uacinfo = uacinfo  # 管理员组 完整性
        self._pinfo = pinfo  # 进程相关信息
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
        self.pid = None
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
        self.session_port = None
        self.target_host = None
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
        self.tunnel_peer_locate_zh = None
        self.tunnel_peer_locate_en = None
        self.comm_channel_session = None
        self.via_exploit = None
        self.via_payload = None
        self.route = []

        self.sysinfo = {}
        self.exploit_uuid = None
        self.available = False
        self.info = None

        # 更新基本信息
        self._set_base_info()

        # 是否需要拓展的信息
        if self._rightinfo or self._pinfo or self._uacinfo:
            result = Xcache.get_session_info(self.sessionid)
            if result is None:
                module_type = "post"
                mname = "multi/gather/session_info"
                opts = {'SESSION': self.sessionid,
                        'PINFO': self._pinfo,
                        'RIGHTINFO': self._rightinfo,
                        'UACINFO': self._uacinfo}
                result = MSFModule.run_msf_module_realtime(module_type=module_type, mname=mname, opts=opts,
                                                           timeout=RPC_SESSION_OPER_LONG_REQ)
                if result is None:
                    Notice.send_warning("更新Session信息失败,请稍后重试",
                                        "Failed to update Session information, please try again later")
                    return
            try:
                result_dict = json.loads(result)
                self._set_advanced_info(result_dict)
                if self._rightinfo and self._pinfo and self._uacinfo:
                    result_dict["update_time"] = int(time.time())
                    Xcache.set_session_info(self.sessionid, json.dumps(result_dict))
            except Exception as E:
                logger.warning(E)
                logger.warning(f"更新Session信息失败,返回消息为{result}")
                logger.warning(result)
                Notice.send_warning("更新Session信息失败,请稍后重试",
                                    "Failed to update Session information, please try again later")

    def _set_base_info(self):
        info = RpcClient.call(Method.SessionGet, [self.sessionid], timeout=RPC_FRAMEWORK_API_REQ)
        if info is None:
            return False
        # 处理linux的no-user问题
        if str(info.get('info')).split(' @ ')[0] == "no-user":
            info['info'] = info.get('info')[10:]

        self.info = info.get('info')
        self.type = info.get('type')
        self.session_host = info.get('session_host')
        self.session_port = info.get('session_port')
        self.target_host = info.get('target_host')
        self.tunnel_local = info.get('tunnel_local')
        self.tunnel_peer = info.get('tunnel_peer')
        self.comm_channel_session = info.get('comm_channel_session')

        self.exploit_uuid = info.get('exploit_uuid')

        self.via_exploit = info.get('via_exploit')
        self.via_payload = info.get('via_payload')
        self.arch = info.get('arch')
        self.platform = info.get('platform')
        self._session_uuid = info.get('uuid')
        self.last_checkin = info.get('last_checkin') // 10 * 10
        self.fromnow = (int(time.time()) - info.get('last_checkin')) // 10 * 10
        self.tunnel_peer_ip = info.get('tunnel_peer').split(":")[0]
        tunnel_peer_ip = info.get('tunnel_peer').split(":")[0]
        self.tunnel_peer_locate_zh = IPGeo.get_ip_geo_str(tunnel_peer_ip, "zh-CN")
        self.tunnel_peer_locate_en = IPGeo.get_ip_geo_str(tunnel_peer_ip, "en-US")
        self.load_powershell = info.get('load_powershell')
        self.load_python = info.get('load_python')

        routestrlist = info.get('routes')
        try:
            if isinstance(routestrlist, list):
                for routestr in routestrlist:
                    routestr.split('/')
                    tmpdict = {"subnet": routestr.split('/')[0], 'netmask': routestr.split('/')[1]}
                    self.route.append(tmpdict)
        except Exception as E:
            logger.error(E)

        try:
            self.user = str(info.get('info')).split(' @ ')[0]
            self.computer = str(info.get('info')).split(' @ ')[1]
        except Exception as _:
            return False
        else:
            try:
                self.os = info.get('advanced_info').get("sysinfo").get("OS")
                self.os_short = info.get('advanced_info').get("sysinfo").get("OS").split("(")[0]
                if len(self.os_short) > 18:
                    self.os_short = f"{self.os_short[0:6]} ... {self.os_short[-6:]}"
            except Exception as _:
                self.os = None
                self.os_short = None

            try:
                self.is_admin = info.get('advanced_info').get("sysinfo").get("IsAdmin")
            except Exception as _:
                pass

            try:
                self.logged_on_users = info.get('advanced_info').get("sysinfo").get("Logged On Users")
            except Exception as _:
                pass

            try:
                self.pid = info.get('advanced_info').get("sysinfo").get("Pid")
            except Exception as _:
                pass

            try:
                self.domain = info.get('advanced_info').get("sysinfo").get("Domain")
            except Exception as _:
                pass

            self.available = True
            return True

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
        if int(time.time()) - self.last_checkin > 90 and self.user is None:
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

    def registry_getvalinfo(self, key, valname, view=0):
        module_type = "post"
        mname = "windows/manage/registry_api"
        opts = {
            'SESSION': self.sessionid,
            'VIEW': view,
            'OPERATION': "registry_getvalinfo",
            'KEY': key,
            'VALNAME': valname,
        }
        result = MSFModule.run_msf_module_realtime(module_type=module_type, mname=mname, opts=opts,
                                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result is None:
            return {'status': False, "message": "MSFRPC Error", "data": None}
        try:
            result = json.loads(result)
            return result
        except Exception as E:
            logger.warning(result)
            return {'status': False, "message": E, "data": None}

    def registry_enumkeys(self, key, view=0):
        module_type = "post"
        mname = "windows/manage/registry_api"
        opts = {
            'SESSION': self.sessionid,
            'VIEW': view,
            'OPERATION': "registry_enumkeys",
            'KEY': key,
        }
        result = MSFModule.run_msf_module_realtime(module_type=module_type, mname=mname, opts=opts,
                                                   timeout=RPC_SESSION_OPER_SHORT_REQ)
        if result is None:
            return {'status': False, "message": "MSFRPC Error", "data": None}
        try:
            result = json.loads(result)
            return result
        except Exception as E:
            logger.warning(result)
            return {'status': False, "message": E, "data": None}
