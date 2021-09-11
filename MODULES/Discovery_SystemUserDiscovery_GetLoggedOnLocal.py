# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取域主机本地正在登录用户"
    DESC_ZH = "模块获取域内远程主机正在登录的用户信息.\n" \
              "模块需要普通的域用户权限,需要远程主机开启远程注册功能.\n" \
              "主机名可以使用<收集所有域主机的信息>模块进行获取"

    NAME_EN = "Get the local login user on domain host"
    DESC_EN = "The module obtains the user information of the remote host in the domain who is logging in.\n" \
              "The module requires ordinary domain user permissions, and the remote host needs to enable the remote registration function.\n" \
              "The host name can be obtained using the <Get the hostname in the domain> module"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1033"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/mc9ze2"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1033/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='ComputerName',
                  tag_zh="主机名", desc_zh="需要查询的主机名",
                  tag_en="Computer Name", desc_en="The computer name to be queried",
                  required=True,
                  ),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        computerName = self.param('ComputerName')
        if session.is_in_domain:
            execute_string = "Get-LoggedOnLocal -ComputerName {} | ConvertTo-JSON -maxDepth 2".format(computerName)
        else:
            return False, "此模块只支持Windows的Meterpreter,且session所属用户必须在域中", "This module only supports Meterpreter of Windows, and the user of the session must be in the domain"
        self.set_execute_string(execute_string)

        return True, None

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                if isinstance(powershell_json_output, list):
                    try:
                        for one in powershell_json_output:
                            ouputstr = "登录主机: {} 域:{} 登录用户:{} 用户SID:{}".format(
                                one.get('ComputerName'),
                                one.get('UserDomain'),
                                one.get('UserName'),
                                one.get('UserSID')[0:11],
                            )
                            self.log_good(ouputstr)
                    except Exception as E:
                        pass
                elif isinstance(powershell_json_output, dict):
                    ouputstr = "登录主机: {} 域:{} 登录用户:{} 用户SID:{}".format(
                        powershell_json_output.get('ComputerName'),
                        powershell_json_output.get('UserDomain'),
                        powershell_json_output.get('UserName'),
                        powershell_json_output.get('UserSID')[0:11],
                    )
                    self.log_good(ouputstr)
                else:
                    self.log_error("脚本无有效输出")
                    self.log_error(powershell_json_output)
            else:
                self.log_error("脚本无有效输出")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
