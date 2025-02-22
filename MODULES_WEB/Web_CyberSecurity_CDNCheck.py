# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :
from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "CDN识别"
    DESC_ZH = "通过cname判断网站是否有CDN"

    NAME_EN = "CDN recognition"
    DESC_EN = "check whether website use CDN by cname"
    MODULETYPE = TAG2TYPE.Web_CyberSecurity_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='Domain',
                  tag_zh="Domain",
                  desc_zh="Domain",
                  tag_en="Domain",
                  desc_en="Domain"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):

        domain_list = []
        for one_input in self.input_list:
            ipdomain = one_input.get("ipdomain")
            if api.is_domain(ipdomain):
                domain_list.append(ipdomain)
        domain_list.append(self.param("Domain"))

        dataset = DataSet()
        for domain in domain_list:
            CDNCheck.check_by_domain(domain, dataset)

        self.log_info("存储数据到数据库", "Save data to database")
        dataset.set_project_id(self.project_id)
        dataset.save_to_db()
