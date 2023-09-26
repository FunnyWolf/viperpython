# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "AlienVault子域名收集"
    DESC_ZH = "调用AlienVault进行子域名"

    NAME_EN = "AlienVault subdomain collection"
    DESC_EN = "Call AlienVault to perform subdomain"
    MODULETYPE = TAG2TYPE.Web_Subdomain_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='Domain',
                  tag_zh="主域名",
                  desc_zh="主域名",
                  tag_en="Domain",
                  desc_en="Domain"),
    ])

    def check(self):
        """执行前的检查函数"""
        return True, ""

    @staticmethod
    def sub_domains(target):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        items = utils.http_req(url, 'get', timeout=(30.1, 50.1)).json()
        results = []
        for item in items["passive_dns"]:
            if item["hostname"].endswith(f".{target}"):
                results.append(item["hostname"])
        return list(set(results))

    def run(self):
        # data,额外需要传输的数据
        # 调用父类函数存储结果(必须调用)
        self.log_info(self.param('Domain'))
        subdomains = self.sub_domains(self.param('Domain'))
        return True
