# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取域控信息"
    DESC = "模块使用powershell脚本获取主机所在域的域控信息,如果主机不在域中,脚本可能报错"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/uf2cs6"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            self.set_execute_string('Get-NetDomainController | ConvertTo-JSON -maxDepth 1')
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且必须在域中"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if isinstance(powershell_json_output, list):
                try:
                    for one in powershell_json_output:
                        outputstr = "名称:{}\n域:{}\n林:{}\nIP地址:{}\nOS版本:{}\n角色:{}".format(
                            one.get('Name'),
                            one.get('Domain'),
                            one.get('Forest'),
                            one.get('IPAddress'),
                            one.get('OSVersion'),
                            one.get('Roles'),

                        )
                        self.log_good(outputstr)
                except Exception as E:
                    pass
            elif isinstance(powershell_json_output, dict):
                outputstr = "名称:{}\n域:{}\n林:{}\nIP地址:{}\nOS版本:{}\n角色:{}".format(
                    powershell_json_output.get('Name'),
                    powershell_json_output.get('Domain'),
                    powershell_json_output.get('Forest'),
                    powershell_json_output.get('IPAddress'),
                    powershell_json_output.get('OSVersion'),
                    powershell_json_output.get('Roles'),

                )
                self.log_good(outputstr)
            else:
                self.log_error("脚本无有效输出")
                self.log_error(data)

        else:
            self.log_error("模块执行失败")
            self.log_error(message)
