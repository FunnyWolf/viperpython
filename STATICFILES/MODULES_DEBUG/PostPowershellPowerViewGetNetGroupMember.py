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
    NAME = "域用户组中的用户信息"
    DESC = "模块获取主机所在域某个用户组中的用户信息,如果主机不在域中,脚本可能报错"
    MODULETYPE = TAG2CH.Discovery
    AUTHOR = "Viper"
    OPTIONS = register_options([
        Option(name='GroupName', name_tag="用户组", type='str', required=True, default='Domain Adminis',
               desc="用户组名称", ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain is not True:
            return False, "模块只支持Windows的Meterpreter,且必须在域中"
        groupName = self.param('GroupName')
        execute_string = "Get-NetGroupMember -GroupName {}".format(groupName)
        self.set_execute_string(execute_string)
        return True, None

    def callback(self, flag, output):
        # 调用父类函数存储结果(必须调用)
        self.store_log(output)
