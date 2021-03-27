# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取域主机的IP信息"
    DESC = "默认收集所控主机的IP地址.\n如果需要收集域内其他主机,如域控或其他域用户ip,请输入主机名作为参数"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/wz0kt4"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='ComputerName', name_tag="主机名", desc="需要查询的主机名"),
        OptionBool(name='AllComputer', name_tag="所有主机", desc="查询域内所有主机的IP地址", default=False),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"
        all_computer = self.param('AllComputer')
        computerName = self.param('ComputerName')

        if all_computer == True:
            if session.is_in_domain:
                execute_string = "Get-DomainComputer | select name | Resolve-IPAddress | ConvertTo-JSON -maxDepth 2"
            else:
                return False, "获取域内其他主机IP地址时,此Session必须在域中"
        else:
            if computerName is not None:
                execute_string = "Resolve-IPAddress -ComputerName {} | ConvertTo-JSON -maxDepth 2".format(computerName)
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
                        ouputstr = "主机名: {} IP地址:{}".format(one.get('ComputerName'), one.get('IPAddress'))
                        self.log_good(ouputstr)
                elif isinstance(powershell_json_output, dict):
                    ouputstr = "主机名: {} IP地址:{}".format(powershell_json_output.get('ComputerName'),
                                                        powershell_json_output.get('IPAddress'))
                    self.log_good(ouputstr)
                else:
                    self.log_error("脚本无有效输出")
            else:
                self.log_error("脚本无有效输出")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
