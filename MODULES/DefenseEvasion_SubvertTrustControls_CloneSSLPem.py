# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from urllib.parse import urlparse

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "克隆Https证书"
    DESC_ZH = "模块读取目标网站证书中的配置信息,并使用此信息克隆一份自签名证书."

    NAME_EN = "Clone Https certificate"
    DESC_EN = "The module reads the configuration information in the target website certificate and uses this information to clone a self-signed certificate."

    MODULETYPE = TAG2TYPE.Defense_Evasion

    ATTCK = ["T1553"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pry6ph"]
    REFERENCES = ["http://www.slideshare.net/ChrisJohnRiley/ssl-certificate-impersonation-for-shits-andgiggles"]
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionStr(name='rhosts',
                  tag_zh="目标网站", desc_zh="目标网站的网址,无需添加https://前缀",
                  tag_en="Target site", desc_en="URL of the target website, no need to add https:// prefix",
                  required=True,
                  ),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "auxiliary"
        self.mname = "gather/impersonate_ssl_api"

    def check(self):
        """执行前的检查函数"""
        rhosts = self.param("rhosts")
        if "https://" in rhosts.lower():
            try:
                urlParse = urlparse(rhosts)
                self.set_msf_option("RHOSTS", urlParse.netloc)
            except Exception as E:
                return False, f"解析网址失败:{E}", f"Failed to parse URL: {E}"
        else:
            self.set_msf_option("RHOSTS", rhosts)

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
        else:
            self.log_info("模块执行完成", "Module operation completed")
            self.log_good(f"请在 <文件列表> 中查看生成的pem文件", "Please check the generated pem file in <Files>")
