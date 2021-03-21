# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME = "获取Windows RDP服务端口"
    DESC = "模块查看主机的RDP服务是否开启,RDP服务的端口号.\n"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1012"]  # ATTCK向量
    AUTHOR = "Viper"
    README = ["https://www.yuque.com/vipersec/module/bc84o2"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1012/"]
    OPTIONS = []

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        session = Session(self._sessionid)
        key = "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp"
        valname = "PortNumber"
        result = session.registry_getvalinfo(key, valname)
        if result.get("status"):
            self.log_good("RDP端口号注册表信息: {}".format(result.get("data")))
        else:
            self.log_error(result.get("message"))
