# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取域主机最后登录用户"
    DESC = "模块获取域内远程主机最后登录的用户信息.\n" \
           "模块需要普通的域用户权限,但是需要远程主机开启远程注册功能.\n" \
           "主机名可以使用<<获取所有域主机的信息>>模块进行获取"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1033"]  # ATTCK向量
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/gbpmkf"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1033/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='ComputerName', name_tag="主机名", desc="需要查询的主机名"),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"

        computerName = self.param('ComputerName')
        if self.param('ComputerName') is not None:
            if session.is_in_domain:
                execute_string = "Get-WMIRegLastLoggedOn -ComputerName {} | ConvertTo-JSON -maxDepth 1".format(
                    computerName)
            else:
                return False, "当填写'主机名'时Session必须在域中"

        else:
            execute_string = "Get-WMIRegLastLoggedOn | ConvertTo-JSON -maxDepth 1"
        self.set_execute_string(execute_string)
        return True, None

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                ouputstr = "登录主机: {} 登录用户:{}".format(powershell_json_output.get('ComputerName'),
                                                     powershell_json_output.get('LastLoggedOn'))
                self.log_good(ouputstr)
            else:
                self.log_error("脚本无有效输出")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
