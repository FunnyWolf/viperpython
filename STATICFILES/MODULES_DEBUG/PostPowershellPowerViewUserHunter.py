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
    NAME = "定位域管理员登录主机"
    DESC = "模块通过遍历域内所有主机,查找域管理员正在登录的主机,指导下一步攻击目标.\n" \
           "(如果模块无结果,可尝试缩小threads再次执行,模块不稳定)"
    MODULETYPE = TAG2CH.Discovery
    AUTHOR = "Viper"
    OPTIONS = register_options([

        Option(name='threads', name_tag="扫描线程数", type='integer', required=True, desc="扫描的最大线程数(1-20)", default=5),

    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("PowerView_dev.ps1")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if session.is_in_domain is not True:
            return False, "模块只支持Windows的Meterpreter,且Session所属用户必须在域中"
        if session.is_admin is not True:
            return False, "Session权限不足,请选择管理员权限Session"
        if session.domain is None:
            return False, "无法获取Session所在域"

        threads = self.param('threads')
        if 1 <= threads <= 20:
            pass
        else:
            return False, "扫描线程参数不正确,请重新设置"

        # 设置参数
        execute_string = "Find-DomainUserLocation -Domain {} -Threads {} -StopOnSuccess| ConvertTo-JSON -maxDepth 2".format(
            session.domain, threads)
        self.set_execute_string(execute_string)
        return True, None

    def callback(self, status, message, data):
        if status:
            powershell_json_output = self.deal_powershell_json_result(data)
            if powershell_json_output is not None:
                if isinstance(powershell_json_output, list):
                    try:
                        for one in powershell_json_output:
                            outputstr = "用户:{} 主机名:{} IP地址:{} 主机域名:{} 本地管理员:{}".format(
                                one.get('UserName'), one.get('ComputerName'), one.get('IPAddress'),
                                one.get('UserDomain'),
                                one.get('LocalAdmin'),
                            )
                            self.log_good(outputstr)
                    except Exception as E:
                        pass
                elif isinstance(powershell_json_output, dict):
                    one = powershell_json_output
                    if one.get('UserName').endswith('$'):
                        return
                    outputstr = "用户:{} 主机名:{} IP地址:{} 主机域名:{} 本地管理员:{}".format(
                        one.get('UserName'), one.get('ComputerName'), one.get('IPAddress'),
                        one.get('UserDomain'),
                        one.get('LocalAdmin'),
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
