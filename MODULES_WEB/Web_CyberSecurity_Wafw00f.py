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
    MODULETYPE = TAG2TYPE.Web_CyberSecurity_Scan
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
        return True, ""

    def run(self):
        dataset = DataSet()
        urls = []
        for one_input in self.input_list:
            url = self.group_url_by_ipdomain_record(one_input)
            if url:
                urls.append(url)

        url = self.param("URL")
        if url is not None:
            urls.append(url)

        WafCheck.scan(urls=urls, dataset=dataset)
        dataset.add_by_urls(urls)

        dataset.set_project_id(self.project_id)
        self.log_info("存储数据到数据库", "Save data to database")
        dataset.save_to_db()
