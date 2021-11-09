# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取域主机最后登录用户"
    DESC_ZH = "模块获取域内远程主机最后登录的用户信息.\n" \
              "模块需要普通的域用户权限,但是需要远程主机开启远程注册功能.\n" \
              "主机名可以使用<获取所有域主机的信息>模块进行获取"

    NAME_EN = "Get the lastlogin user of the domain host"
    DESC_EN = "The module obtains the last logged-in user information of the remote host in the domain.\n" \
              "The module requires ordinary domain user permissions, but the remote host needs to enable the remote registration function.\n" \
              "The host name can be obtained using the <Get the hostname in the domain> module"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1033"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/qimyao"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1033/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionStr(name='ComputerName',
                  tag_zh="主机名", desc_zh="需要查询的主机名",
                  tag_en="Computer Name", desc_en="The computer name to be queried",
                  ),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        computerName = self.param('ComputerName')
        if self.param('ComputerName') is not None:
            if session.is_in_domain:
                execute_string = f"Get-WMIRegLastLoggedOn -ComputerName {computerName} | ConvertTo-JSON -maxDepth 1"
            else:
                return False, "当填写'主机名'时Session必须在域中", "Get the session must be in the domain when filling in the'Computer Name'"

        else:
            execute_string = "Get-WMIRegLastLoggedOn | ConvertTo-JSON -maxDepth 1"
        self.set_execute_string(execute_string)
        return True, None

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                self.log_good(
                    f"登录主机: {powershell_json_output.get('ComputerName')} 登录用户:{powershell_json_output.get('LastLoggedOn')}",
                    f"Login host: {powershell_json_output.get('ComputerName')} Login user: {powershell_json_output.get('LastLoggedOn')}")
            else:
                self.log_error("脚本无有效输出", "Script has no valid output")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
