# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "wafw00f WAF识别"
    DESC_ZH = "调用wafw00f进行WAF识别"

    NAME_EN = "wafw00f WAF recognition"
    DESC_EN = "Call wafw00f for WAF recognition"
    MODULETYPE = TAG2TYPE.Web_PortService_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='URL',
                  tag_zh="URL",
                  desc_zh="URL",
                  tag_en="URL",
                  desc_en="URL"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        url = self.param("URL")
        pret = utils.urlParser(url)
        if pret is None:
            return False, "输入的URL无效", "Invalid URL"
        return True, ""

    def run(self):
        ip_list = []

        for one_input in self.input_list:
            ipdomain = one_input.get("ipdomain")
            ip_list.append(ipdomain)

        url = self.param("URL")
        items = WafCheck.check([url])
        DataStore.wafcheck_result(items, project_id=self.project_id, source={})
