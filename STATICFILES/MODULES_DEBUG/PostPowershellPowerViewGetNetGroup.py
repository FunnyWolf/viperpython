# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

#
#
from PostModule.lib.ModuleTemplate import PostMSFPowershellFunctionModule, TAG2CH


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "域用户组信息"
    DESC = "模块获取主机所在域的用户组信息,如果主机不在域中,脚本可能报错"
    MODULETYPE = TAG2CH.Discovery
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if session.is_in_domain:
            self.set_execute_string('Get-NetGroup')
            return True, None
        else:
            return False, "模块只支持Windows的Meterpreter,且必须在域中"

    def callback(self, flag, output):
        # 调用父类函数存储结果(必须调用)
        self.store_log(output)
