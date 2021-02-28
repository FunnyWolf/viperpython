# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

import os

import donut

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME = "PE文件转Shellcode"
    DESC = "将.NET的EXE/DLL,windows PE文件转化为shellcode文件.\n" \
           "支持命令行参数.\n" \
           "当前只支持win2008sp1以上版本."

    MODULETYPE = TAG2CH.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1116"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1116/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionFileEnum(ext=['exe', 'EXE', 'dll', 'DLL']),
        OptionEnum(name='ARCH', name_tag="ARCH", desc="选择Arch", required=True,
                   default=3,
                   enum_list=[
                       {'name': 'x86', 'value': 1},
                       {'name': 'amd64', 'value': 2},
                       {'name': 'x86+amd64', 'value': 3},
                   ]),
        OptionStr(name='ARGUMENTS', name_tag="命令行参数", desc="运行exe时输入的参数", option_length=24),
        OptionStr(name='cls', name_tag=".NET Class名称", desc=".NET Class名称(用于.NET DLL)"),
        OptionStr(name='method', name_tag=".NET 函数名称", desc=".NET 函数名称(用于.NET DLL)"),
        OptionStr(name='shellcodefilename', name_tag="shellcode文件名称(无需后缀)", desc="输出的shellcode文件名称,默认为输入文件名.bin"),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.session = None

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):

        pe_file_path = self.get_option_filepath()
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
                self.log_status(".NET DLL 模式")
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
