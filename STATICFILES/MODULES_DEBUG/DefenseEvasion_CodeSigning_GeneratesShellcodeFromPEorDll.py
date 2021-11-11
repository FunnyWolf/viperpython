# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import os

import donut

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME_ZH = "PE文件转Shellcode"
    DESC_ZH = "将.NET的EXE/DLL,windows PE文件转化为shellcode文件.\n" \
              "支持命令行参数.\n" \
              "当前只支持win2008sp1以上版本."

    NAME_EN = "Hijacking Windows digital signature authentication"
    DESC_EN = "Modify the Windows default digital certificate authentication program so that the system certifies that all digital signatures are valid by default.\n" \
              "The module will affect the running signature authentication of all exe in the system, please use it with caution."

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1116"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1116/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionFileEnum(ext=['exe', 'EXE', 'dll', 'DLL']),
        OptionEnum(name='ARCH', tag_zh="ARCH", tag_en="ARCH", desc_zh="选择Arch", desc_en="选择Arch", required=True,
                   default=3,
                   enum_list=[
                       {'tag_zh': 'x86', 'tag_en': 'x86', 'value': 1},
                       {'tag_zh': 'amd64', 'tag_en': 'amd64', 'value': 2},
                       {'tag_zh': 'x86+amd64', 'tag_en': 'x86+amd64', 'value': 3},
                   ]),
        OptionStr(name='ARGUMENTS', tag_zh="命令行参数", tag_en="命令行参数", desc_en="选择Arch", desc_zh="运行exe时输入的参数", length=24),
        OptionStr(name='cls', tag_zh=".NET Class名称", tag_en=".NET Class名称", desc_en="选择Arch",
                  desc_zh=".NET Class名称(用于.NET DLL)"),
        OptionStr(name='method', tag_zh=".NET 函数名称", tag_en=".NET 函数名称", desc_en="选择Arch",
                  desc_zh=".NET 函数名称(用于.NET DLL)"),
        OptionStr(name='shellcodefilename', tag_zh="shellcode文件名称(无需后缀)", desc_en="选择Arch", tag_en="ARCH",
                  desc_zh="输出的shellcode文件名称,默认为输入文件名.bin"),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        pe_file_path = self.get_fileoption_filepath()
        if pe_file_path is None:
            self.log_error("非docker部署不支持此模块,请使用原版donut工具")
            return

        arch = self.param("ARCH")
        params = self.param("ARGUMENTS")

        cls = self.param("cls")
        method = self.param("method")

        if params is None:
            params = ""
        try:
            if cls is not None and method is not None:
                self.log_info(".NET DLL 模式")
                shellcode = donut.create(
                    file=pe_file_path,
                    arch=arch,
                    cls=cls,
                    method=method,
                    params=params,
                )
            else:
                shellcode = donut.create(
                    file=pe_file_path,
                    arch=arch,
                    params=params,
                )
        except Exception as E:
            self.log_error("donut运行异常!")
            self.log_except(E)
            return
        if shellcode is None:
            self.log_error("donut无法转换此文件!")
            return

        if self.param("shellcodefilename") is not None:
            output_filename = "{}.bin".format(self.param("shellcodefilename"))
        else:
            output_filename = "{}.bin".format(os.path.splitext(self.get_option_filename())[0])
        if self.write_to_loot(output_filename, shellcode):
            self.log_good("转换完成,新文件名 : {}".format(output_filename))
        else:
            self.log_error("shellcode写入文件失败")
        try:
            os.remove("loader.bin")
        except Exception as E:
            print(E)
