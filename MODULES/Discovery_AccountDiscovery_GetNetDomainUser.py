# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取所有域用户"
    DESC_ZH = "模块获取主机所在域的所有域用户信息,如果主机不在域中,脚本可能报错"

    NAME_EN = "Get all domain users"
    DESC_EN = "The module obtains all domain user information in the domain where the host is located. If the host is not in the domain, the script may report an error"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1087"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/ozet21"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1087/"]
    AUTHOR = ["Viper"]

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件
        self.set_execute_string('Get-DomainUser | select memberof,whenchanged,useraccountcontrol,'
                                'name,lastlogon,pwdlastset,displayname,whencreated,userprincipalname | Convertto-JSON -maxdepth 2')

    def check(self):

        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且主机必须在域中", "This module only supports Meterpreter of Windows, and the host must be in the domain"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                if isinstance(powershell_json_output, list):
                    try:
                        for one in powershell_json_output:
                            self.log_good(
                                f"用户:{one.get('name')} 显示名称:{one.get('displayname')} 域内标识:{one.get('userprincipalname')} 账户控制:{one.get('useraccountcontrol')}\n"
                                f"最后登录时间:{one.get('lastlogon')} 账户更改时间:{one.get('whenchanged')} 最后设置密码时间:{one.get('pwdlastset')} 账户创建时间:{one.get('whencreated')}"
                                f"User: {one.get('name')} Display name: {one.get('displayname')} Domain ID: {one.get('userprincipalname')} Account control: {one.get('useraccountcontrol ')}\n"
                                f"Last login time: {one.get('lastlogon')} Account change time: {one.get('whenchanged')} Last password setting time: {one.get('pwdlastset')} Account creation time: {one.get('whencreated')}")
                    except Exception as E:
                        pass
                elif isinstance(powershell_json_output, dict):
                    one = powershell_json_output
                    self.log_good(
                        f"用户:{one.get('name')} 显示名称:{one.get('displayname')} 域内标识:{one.get('userprincipalname')} 账户控制:{one.get('useraccountcontrol')}\n"
                        f"最后登录时间:{one.get('lastlogon')} 账户更改时间:{one.get('whenchanged')} 最后设置密码时间:{one.get('pwdlastset')} 账户创建时间:{one.get('whencreated')}",
                        f"User: {one.get('name')} Display name: {one.get('displayname')} Domain ID: {one.get('userprincipalname')} Account control: {one.get('useraccountcontrol ')}\n"
                        f"Last login time: {one.get('lastlogon')} Account change time: {one.get('whenchanged')} Last password setting time: {one.get('pwdlastset')} Account creation time: {one.get('whencreated')}")
                else:
                    self.log_error("脚本无有效输出", "Script has no valid output")
                    self.log_error(powershell_json_output, powershell_json_output)

            else:
                self.log_error("脚本无有效输出", "Script has no valid output")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
