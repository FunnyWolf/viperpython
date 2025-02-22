# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "360 Quake子域名信息收集"
    DESC_ZH = "调用360 Quake进行子域名"

    NAME_EN = "360 Quake subdomain collection"
    DESC_EN = "Call 360 Quake to perform subdomain"
    MODULETYPE = TAG2TYPE.Web_Network_Scan
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

        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        self.quake_client.init_conf_from_cache()
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
            source_key = f"domain:\"{domain}\""
            flag = self.quake_client.search_by_query_str(source_key, dataset)
            self.log_info(f"Quake Search : {source_key} Count: {flag}")

        self.log_info("存储数据到数据库", "Save data to database")
        dataset.set_project_id(self.project_id)
        dataset.save_to_db()
        return True
