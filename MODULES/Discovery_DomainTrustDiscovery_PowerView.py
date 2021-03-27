# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取域信任信息"
    DESC = "获取主机所在域/林的域信任信息"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", ]  # 所需权限
    ATTCK = ["T1482"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/tg0fuf"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1482/"]
    AUTHOR = "Viper"
    OPTIONS = register_options([
        OptionEnum(name='action',
                   name_tag="选项",
                   desc="选择Arch",
                   required=True,
                   default="Get-DomainTrust",
                   enum_list=[
                       {'name': "域信任信息", 'value': "Get-DomainTrust"},
                       {'name': "林信任信息", 'value': "Get-ForestTrust"},

                   ])
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            action = self.param("action")
            self.set_execute_string(action)
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且必须在域中"

    def callback(self, status, message, data):
        if status:
            self.log_good("模块执行成功")
            self.log_raw(data)
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
