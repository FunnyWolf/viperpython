# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :
from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "nuclei 扫描"
    DESC_ZH = "调用nuclei 扫描"

    NAME_EN = "nuclei scan"
    DESC_EN = "Call nuclei scan"
    MODULETYPE = TAG2TYPE.Web_CyberSecurity_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='URL',
                  tag_zh="URL",
                  desc_zh="URL (e.g.: http://honey.scanme.sh)",
                  tag_en="URL",
                  desc_en="URL (e.g.: http://honey.scanme.sh)",
                  default="http://honey.scanme.sh"
                  ),
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

        nuclei_obj = NucleiAPI()
        nuclei_obj.scan(urls=urls, dataset=dataset)
        dataset.add_by_urls(urls)
        self.log_info("存储数据到数据库", "Save data to database")
        dataset.set_project_id(self.project_id)
        dataset.save_to_db()
