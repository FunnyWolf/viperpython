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

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):
        self.log_info(f"主域名: {self.param('Domain')}", f"Domain: {self.param('Domain')}")
        subdomains = AlienVault.list_subdomains(self.param('Domain'))
        results = []
        for subdomain in subdomains:
            results.append({"ipdomain": subdomain})
        DataStore.subdomain_result(results, self.project_id)
        self.log_good(f"查找到 {len(subdomains)} 个子域名", f"Found {len(subdomains)} subdomains")
        return True