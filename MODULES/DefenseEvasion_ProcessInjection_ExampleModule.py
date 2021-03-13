# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFCSharpModule):
    NAME = "PostMSFCSharpModule演示模块"
    DESC = "模块用于演示PostMSFCSharpModule模块的基本编写方法\n"
    MODULETYPE = TAG2CH.Defense_Evasion  # '防御绕过'模块,可以自行更改
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1003"]  # ATTCK向量
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/ckhgsk"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1003/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)

    def check(self):
        """执行前的检查函数"""
        # 设置执行的c#的exe名称,不需要带exe后缀名
        # 请确保编译.net2.0及.net4.0两个版本的exe
        # 文件名样例 TestAssembly-N20.exe TestAssembly-N40.exe
        # 将文件上传到Docker /root/metasploit-framwork/scripts/csharp/目录下
        # 或将文件通过 "文件列表"功能上传到loot目录下
        self.set_assembly("TestAssembly")
        # 执行文件时的输入参数  .\TestAssembly-N20.exe iam_args
        self.set_arguments("iam_args")
        # 文件执行,在读取输出前的等待秒数
        self.set_execute_wait(5)

        session = Session(self._sessionid)

        if session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter"

        return True, None

    def callback(self, status, message, data):
        assembly_out = self.get_console_output(status, message, data)
        self.log_raw(assembly_out)
