# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from urllib.parse import urlparse

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "克隆Https证书"
    DESC = "模块读取目标网站证书中的配置信息,并使用此信息克隆一份自签名证书."
    MODULETYPE = TAG2CH.Defense_Evasion

    ATTCK = ["T1553"]  # ATTCK向量
    REFERENCES = ["http://www.slideshare.net/ChrisJohnRiley/ssl-certificate-impersonation-for-shits-andgiggles"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionStr(name='rhosts', name_tag="目标网站", required=True, desc="目标网站的网址,无需添加https://前缀"),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "auxiliary"
        self.mname = "gather/impersonate_ssl_api"

    def check(self):
        """执行前的检查函数"""
        rhosts = self.param("rhosts")
        if "https://" in rhosts.lower():
            try:
                urlParse = urlparse(rhosts)
                self.set_option("RHOSTS", urlParse.netloc)
            except Exception as E:
                return False, f"解析网址失败:{E}"
        else:
            self.set_option("RHOSTS", rhosts)

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败,失败原因:{}".format(message))
        else:
            self.log_good("模块执行成功")
            self.log_good(f"请在 <文件列表> 中查看生成的pem文件")
