# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "360 Quake子域名收集"
    DESC_ZH = "调用360 Quake进行子域名"

    NAME_EN = "360 Quake subdomain collection"
    DESC_EN = "Call 360 Quake to perform subdomain"
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
        OptionInt(name='MaxSize',
                  tag_zh="最大数量",
                  desc_zh="最大数量",
                  tag_en="MaxSize",
                  desc_en="MaxSize",
                  default=1000),
    ])

    def check(self):
        """执行前的检查函数"""
        if self.param("MaxSize") > 1000:
            return False, "MaxSize不能大于1000"
        elif self.param("MaxSize") < 0:
            return False, "MaxSize不能小于0"
        return True, ""

    def run(self):
        self.log_info(f"主域名: {self.param('Domain')}", f"Domain: {self.param('Domain')}")
        Quake().get_subdomain_data()
        subdomains = self.sub_domains(self.param('Domain'))
        self.log_info(f"子域名列表: ", f"Subdomain List:")
        for subdomain in subdomains:
            self.log_good(subdomain)
            if not IPDomain.add_or_update(ipdomain=subdomain, type="domain", source="AlienVault"):
                self.log_error("添加失败", "Add Failed")
        self.log_good(f"查找到 {len(subdomains)} 个子域名", f"Found {len(subdomains)} subdomains")
        self.log_info("模块执行完成", "Module operation completed")
        return True
