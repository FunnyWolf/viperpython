# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取域内主机名"
    DESC_ZH = "模块获取主机所在域的所有域主机名,如果主机不在域中,脚本可能报错."

    NAME_EN = "Get the hostname in the domain"
    DESC_EN = "The module obtains all domain host names of the domain where the host is located.\n" \
              "If the host is not in the domain, the script may report an error."

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/ivaxm9"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = ["Viper"]

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件
        self.set_execute_string('Get-NetComputer')

    def check(self):

        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            self.set_execute_string('Get-NetComputer')
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且session所属用户必须在域中", "This module only supports Meterpreter of Windows, and the user of the session must be in the domain"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = data.split("\n")
            if isinstance(powershell_json_output, list) and len(powershell_json_output) > 0:
                try:
                    for one in powershell_json_output:
                        if one is None or len(one) == 0:
                            continue
                        else:
                            self.log_good(f"主机名: {one}", f"Hostname: {one}")
                except Exception as E:
                    pass
            else:
                self.log_error("脚本无有效输出", "Script has no valid output")
                self.log_error(powershell_json_output, powershell_json_output)

        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
