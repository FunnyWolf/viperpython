# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows已安装软件"
    DESC_ZH = "获取当前Windows已安装软件列表.可以通过此信息查找可能的利用链或当前主机的用途."

    NAME_EN = "Windows installed software"
    DESC_EN = "Get the list of currently installed software in Windows.\n" \
              " You can use this information to find possible exploit chains or the purpose of the current host."

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1010"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/rgfmz8"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1010/"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = []

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/gather/enum_applications_api"

    def check(self):
        """执行前的检查函数"""

        self.session = Session(self._sessionid)
        if self.session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        self.log_info("模块结果:", "Module results")
        self.log_raw(data)
