# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取Windows网络共享"
    DESC_ZH = "模块获取主机本地共享信息或域内其他主机共享信息"

    NAME_EN = "Get Windows network share"
    DESC_EN = "The module obtains the local shared information of the host or the shared information of other hosts in the domain"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", ]  # 所需权限
    ATTCK = ["T1135"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/dc5npu"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1135/"]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='ComputerName',
                  tag_zh="主机名", desc_zh="需要查询的主机名,如未输入则查询本机共享",
                  tag_en="Computer Name",
                  desc_en="The host name that needs to be queried, if not entered, the local share will be queried",
                  ),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:
            computerName = self.param("ComputerName")
            if computerName is not None:
                self.set_execute_string(f"Get-NetShare -ComputerName {computerName} | select name,ComputerName")
            else:
                self.set_execute_string("Get-NetShare | select name")
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且主机必须在域中", "This module only supports Meterpreter of Windows, and the host must be in the domain"

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
