# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "获取.Net framework版本列表"
    DESC_ZH = "模块获取主机已安装的.Net framework版本."

    NAME_EN = "Get .Net framework versions"
    DESC_EN = "The module obtains the version of the .Net framework that the host has installed."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1012"]  # ATTCK向量
    AUTHOR = ["Viper"]
    README = ["https://www.yuque.com/vipersec/module/wz43gg"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1012/"]
    OPTIONS = []

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        session = Session(self._sessionid)
        key = "HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\NET Framework Setup\\\\NDP"
        result = session.registry_enumkeys(key)
        if result.get("status"):
            self.log_good("已安装.Net framework版本:", "Installed .Net framework version:")
            version_list = result.get("data")
            for one in version_list:
                if one.startswith('v'):
                    self.log_good(one, one)
        else:
            self.log_error(result.get("message"), result.get("message"))
