# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME_ZH = "获取Windows权限组"
    DESC_ZH = "模块获取主机本地用户组及域用户组"

    NAME_EN = "Get Windows permission group"
    DESC_EN = "The module obtains the host local user group and domain user group"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", ]  # 所需权限
    ATTCK = ["T1069"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/bu4ozg"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1069/"]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionEnum(name='action',
                   tag_zh="选项", desc_zh="可以选择获取Session所在域信任信息及林信任信息",
                   tag_en="Action",
                   desc_en="You can choose to obtain the trust information of the domain where the Session is located and the forest trust information",
                   required=True,
                   default="Get-NetLocalGroup  | select GroupName",
                   enum_list=[
                       {'tag_zh': "本地用户组", 'tag_en': "Local user group",
                        'value': "Get-NetLocalGroup  | select GroupName"},
                       {'tag_zh': "域用户组", 'tag_en': "Domain User Group",
                        'value': "Get-DomainGroup | select name,samaccountname"},
                   ]),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:
            action = self.param("action")
            self.set_execute_string(action)
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
