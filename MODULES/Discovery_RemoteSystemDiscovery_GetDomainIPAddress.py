# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取域主机的IP"
    DESC_ZH = "默认收集当前主机的IP地址.\n如果需要收集域内其他主机,如域控或其他域用户ip,请输入主机名作为参数"

    NAME_EN = "Get the IP of the domain host"
    DESC_EN = "The IP address of the current host is collected by default.\n" \
              "If you need to collect other hosts in the domain, such as domain controllers or other domain user IPs, please enter the host name as a parameter"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/wz0kt4"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionStr(name='ComputerName',
                  tag_zh="主机名", desc_zh="需要查询的主机名",
                  tag_en="Computer Name", desc_en="The computer name to be queried",
                  ),
        OptionBool(name='AllComputer',
                   tag_zh="所有主机", desc_zh="查询域内所有主机的IP地址",
                   tag_en="All Computers", desc_en="Query the IP addresses of all computers in the domain",
                   default=False),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        all_computer = self.param('AllComputer')
        computerName = self.param('ComputerName')

        if all_computer == True:
            if session.is_in_domain:
                execute_string = "Get-DomainComputer | select name | Resolve-IPAddress | ConvertTo-JSON -maxDepth 2"
            else:
                return False, "获取域内其他主机IP地址时,此Session必须在域中", "When obtaining the IP addresses of other hosts in the domain, this session must be in the domain"
        else:
            if computerName is not None:
                execute_string = f"Resolve-IPAddress -ComputerName {computerName} | ConvertTo-JSON -maxDepth 2"
            else:
                execute_string = "Resolve-IPAddress|ConvertTo-JSON -maxDepth 2"
        self.set_execute_string(execute_string)

        return True, None

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:

                if isinstance(powershell_json_output, list):
                    for one in powershell_json_output:
                        self.log_good(f"主机名: {one.get('ComputerName')} IP地址:{one.get('IPAddress')}",
                                      f"Hostname: {one.get('ComputerName')} IPAddress: {one.get('IPAddress')}")
                elif isinstance(powershell_json_output, dict):
                    ouputstr = f"主机名: {powershell_json_output.get('ComputerName')} IP地址:{powershell_json_output.get('IPAddress')}"
                    self.log_good(
                        f"主机名: {powershell_json_output.get('ComputerName')} IP地址:{powershell_json_output.get('IPAddress')}",
                        f"Hostname: {powershell_json_output.get('ComputerName')} IPAddress: {powershell_json_output.get('IPAddress')}")
                else:
                    self.log_error("脚本无有效输出", "Script has no valid output")
            else:
                self.log_error("脚本无有效输出", "Script has no valid output")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
