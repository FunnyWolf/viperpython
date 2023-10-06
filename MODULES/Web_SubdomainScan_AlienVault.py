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
    def sub_domains(domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        items = utils.http_req(url, 'get', timeout=(30.1, 50.1)).json()
        results = []
        for item in items["passive_dns"]:
            if item["hostname"].endswith(f".{domain}"):
                results.append(item["hostname"])
        return list(set(results))

    def run(self):
        self.log_info(f"主域名: {self.param('Domain')}", f"Domain: {self.param('Domain')}")
        subdomains = self.sub_domains(self.param('Domain'))
        self.log_info(f"子域名列表: ", f"Subdomain List:")
        for subdomain in subdomains:
            self.log_good(subdomain)
            if not IPDomain.add_or_update(ipdomain=subdomain, type="domain", source="AlienVault",
                                          source_key=f"passive_dns:{self.param('Domain')}"):
                self.log_error("添加失败", "Add Failed")
        self.log_good(f"查找到 {len(subdomains)} 个子域名", f"Found {len(subdomains)} subdomains")
        self.log_info("模块执行完成", "Module operation completed")
        return True
