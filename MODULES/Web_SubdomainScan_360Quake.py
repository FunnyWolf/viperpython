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
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        if self.quake_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        source_key = f"domain:\"{self.param('Domain')}\""
        msg, items = self.quake_client.get_json_data(source_key)
        if items is None:
            return False
        self.quake_client.store_query_result(items, project_id=self.project_id, source={})
        return True
