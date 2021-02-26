# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

#
#
from PostModule.lib.ModuleTemplate import PostMSFPowershellFunctionModule, TAG2CH
from PostModule.lib.OptionAndResult import Option, register_options
from PostModule.lib.Session import Session


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "域主机的进程信息"
    DESC = "模块收集域主机的进程信息,可以输入域内主机名来查看远程主机的进程信息(远程查看需要对应主机开启远程相关权限)"
    MODULETYPE = TAG2CH.Discovery
    AUTHOR = "Viper"
    OPTIONS = register_options([
        Option(name='ComputerName', name_tag="主机名", type='str', required=False,
               desc="需要查询的主机名", ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件
        self.set_execute_string('Get-NetProcess')

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "模块只支持Windows的Meterpreter"
        computerName = self.param('ComputerName')
        if computerName is None:
            execute_string = "Get-NetProcess"
        else:
            if session.is_in_domain:
                execute_string = "Get-NetProcess -ComputerName {}".format(computerName)
            else:
                return False, "模块只支持Windows的Meterpreter,且必须在域中"
        self.set_execute_string(execute_string)
        return True, None

    def callback(self, flag, output):
        # 调用父类函数存储结果(必须调用)
        self.store_log(output)
