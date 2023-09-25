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

    def __init__(self, custom_param):
        super().__init__(custom_param)
        pass

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):
        # data,额外需要传输的数据
        # 调用父类函数存储结果(必须调用)
        print(self.param)
        return True
