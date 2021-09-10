# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取域基本信息"
    DESC_ZH = "模块使用powershell脚本获取主机所在域的基本信息,如果主机不在域中,脚本可能报错"

    NAME_EN = "Get basic domain information"
    DESC_EN = "The module uses the powershell script to obtain the basic information of the domain where the host is located.\n" \
              "If the host is not in the domain, the script may report an error"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/ybuf4d"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            self.set_execute_string('Get-Domain | ConvertTo-JSON -maxDepth 1')
            return True, None
        else:
            return False, "Session必须在域中"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if isinstance(powershell_json_output, list) and len(powershell_json_output) > 0:
                try:
                    for one in powershell_json_output:
                        outputstr = "域名: {}\n域控: {}\n域林: {}\nRidOwner: {}".format(
                            one.get('Name'),
                            one.get('DomainControllers'),
                            one.get('Forest'),
                            one.get('RidRoleOwner'),
                        )
                        self.log_good(outputstr)
                except Exception as E:
                    pass
            elif isinstance(powershell_json_output, dict):
                outputstr = "域名: {}\n域控: {}\n域林: {}\nRidOwner: {}".format(
                    powershell_json_output.get('Name'),
                    powershell_json_output.get('DomainControllers'),
                    powershell_json_output.get('Forest'),
                    powershell_json_output.get('RidRoleOwner'),
                )
                self.log_good(outputstr)
            else:
                self.log_error("脚本无有效输出")
                self.log_error(powershell_json_output)





        else:
            self.log_error("模块执行失败")
            self.log_error(message)
