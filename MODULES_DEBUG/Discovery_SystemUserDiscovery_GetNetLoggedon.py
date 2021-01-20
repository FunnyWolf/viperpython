# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

#
#
from PostModule.lib.ModuleTemplate import PostMSFPowershellFunctionModule, TAG2CH
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Session import Session


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取域内主机正在登录的用户"
    DESC = "模块收集域内某主机正在登录的用户信息,当主机名为空时默认收集本机正在登录用户信息.\n" \
           "当选择收集域内所有主机正在登录的用户信息时,当域内主机较多时模块可能运行超时\n" \
           "(此模块运行不稳定)"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1033"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1033/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        Option(name='ComputerName', name_tag="主机名", type='str', required=False,
               desc="需要查询的主机名", ),
        Option(name='ALL', name_tag="域内所有主机", type='bool', required=False, desc="收集域内所有主机正在登录用户信息",
               default=False),
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
        if computerName is not None:
            if session.is_in_domain:
                execute_string = "Get-NetLoggedon -ComputerName {} | ConvertTo-JSON -maxDepth 2".format(
                    computerName)
            else:
                return False, "当填写'主机名'时Session必须在域中"
        elif self.param('Range'):
            if session.is_in_domain:
                execute_string = 'Get-DomainComputer | Get-NetLoggedon | ConvertTo-JSON -maxDepth 2'
            else:
                return False, "Session必须在域中"
        else:
            execute_string = 'Get-NetLoggedon | ConvertTo-JSON -maxDepth 2'

        self.set_execute_string(execute_string)
        return True, None

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                if isinstance(powershell_json_output, list):
                    try:
                        for one in powershell_json_output:
                            if one.get('UserName').endswith('$'):
                                continue
                            outputstr = "用户:{} 主机名:{} 登录域:{} 登录服务器:{} 认证域:{}".format(
                                one.get('UserName'), one.get('ComputerName'), one.get('LogonDomain'),
                                one.get('LogonServer'),
                                one.get('AuthDomains'),
                            )
                            self.log_good(outputstr)
                    except Exception as E:
                        pass
                elif isinstance(powershell_json_output, dict):
                    one = powershell_json_output
                    if one.get('UserName').endswith('$'):
                        return
                    outputstr = "用户:{} 主机名:{} 登录域:{} 登录服务器:{} 认证域:{}".format(
                        one.get('UserName'), one.get('ComputerName'), one.get('LogonDomain'),
                        one.get('LogonServer'),
                        one.get('AuthDomains'),
                    )
                    self.log_good(outputstr)
                else:
                    self.log_error("脚本无有效输出")
                    self.log_error(powershell_json_output)

            else:
                self.log_error("脚本无有效输出")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
