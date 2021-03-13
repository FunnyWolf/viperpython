# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取域内主机名"
    DESC = "模块获取主机所在域的所有域主机名,如果主机不在域中,脚本可能报错."
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1018"]  # ATTCK向量
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/sp72lr"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1018/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件
        self.set_execute_string('Get-NetComputer')

    def check(self):

        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            self.set_execute_string('Get-NetComputer')
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且必须在域中"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = data.split("\n")
            if isinstance(powershell_json_output, list) and len(powershell_json_output) > 0:
                try:
                    for one in powershell_json_output:
                        if one is None or len(one) == 0:
                            continue
                        else:
                            ouputstr = "主机名: {}".format(one)
                        self.log_good(ouputstr)
                except Exception as E:
                    pass
            else:
                self.log_error("脚本无有效输出")
                self.log_error(powershell_json_output)

        else:
            self.log_error("模块执行失败")
            self.log_error(message)
