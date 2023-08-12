# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "判断Session是否运行在容器中"
    DESC_ZH = "判断Session是否运行在容器中\n"

    NAME_EN = "Check If Session Is Running In Container"
    DESC_EN = "Check If Session Is Running In Container\n"
    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Linux"]  # 平台
    PERMISSIONS = ["User", "Root"]  # 所需权限
    ATTCK = ["T1497"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/dyiiewfkgpevcn1a"]
    REFERENCES = []
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "linux/gather/checkcontainer_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_linux is not True:
            return False, "此模块只支持linxu的Meterpreter", "This module only supports Meterpreter for Linux"
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return

        if data is None:
            self.log_info("Session不在容器中", "Session is not in the container")
            return
        else:
            self.log_info(f"Session在 [{data}] 容器中", f"Session is in [{data}] container")
