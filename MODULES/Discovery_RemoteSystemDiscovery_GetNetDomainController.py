# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取域控信息"
    DESC_ZH = "模块使用powershell脚本获取主机所在域的域控信息,如果主机不在域中,脚本可能报错"

    NAME_EN = "Get Domain controller information"
    DESC_EN = "The module uses the powershell script to obtain the domain control information of the domain where the host is located.\n" \
              "If the host is not in the domain, the script may report an error"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/oddhnc"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            self.set_execute_string('Get-NetDomainController | ConvertTo-JSON -maxDepth 1')
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且session所属用户必须在域中", "This module only supports Meterpreter of Windows, and the user of the session must be in the domain"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if isinstance(powershell_json_output, list):
                try:
                    for one in powershell_json_output:
                        outputstr = f"名称:{one.get('Name')}\n域:{one.get('Domain')}\n林:{one.get('Forest')}\nIP地址:{one.get('IPAddress')}\nOS版本:{one.get('OSVersion')}\n角色:{one.get('Roles')}"
                        self.log_good(outputstr, "XXX")
                except Exception as E:
                    pass
            elif isinstance(powershell_json_output, dict):
                outputstr = f"名称:{powershell_json_output.get('Name')}\n域:{powershell_json_output.get('Domain')}\n林:{powershell_json_output.get('Forest')}\nIP地址:{powershell_json_output.get('IPAddress')}\nOS版本:{powershell_json_output.get('OSVersion')}\n角色:{powershell_json_output.get('Roles')}"
                self.log_good(outputstr, "XXX")
            else:
                self.log_error("脚本无有效输出", "XXX")
                self.log_error(data, "XXX")

        else:
            self.log_error("模块执行失败", "XXX")
            self.log_error(message, "XXX")
