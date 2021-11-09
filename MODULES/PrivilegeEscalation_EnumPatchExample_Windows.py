# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "获取Windows补丁列表"
    DESC_ZH = "获取Windows主机的补丁列表.\n" \
              "模块用于演示如何在不修改MSF模块的情况下编写Viper模块."

    NAME_EN = "Get Windows patches"
    DESC_EN = "Get the patch list of the Windows host.\n" \
              "The module is used to demonstrate how to write a Viper module without modifying the MSF module."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Privilege_Escalation
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator"]  # 所需权限
    ATTCK = ["T1088"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/tcwg8s"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1088/"]
    AUTHOR = ["Viper"]

    OPTIONS = []

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid, rightinfo=True, uacinfo=True)
        self.session = session
        if session.is_windows:
            self.opts["SESSION"] = self._sessionid  # 设置msf模块的options
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        return True, None

    def run(self):
        # 获取用户输入的参数
        module_ouput = MsfModule.run_with_output(module_type="post",
                                                 mname="windows/gather/enum_patches",
                                                 opts=self.opts)
        self.log_raw(module_ouput)
