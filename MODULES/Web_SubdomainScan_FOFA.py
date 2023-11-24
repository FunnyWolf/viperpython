# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "FOFA子域名收集"
    DESC_ZH = "调用FOFA进行子域名"

    NAME_EN = "FOFA subdomain collection"
    DESC_EN = "Call FOFA to perform subdomain"
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
        self.fofa_client = FOFAClient()

    def check(self):
        """执行前的检查函数"""
        if self.fofa_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        self.log_info(f"主域名: {self.param('Domain')}", f"Domain: {self.param('Domain')}")
        source_key = f"host~=\".+\\.{self.param('Domain')}\""
        source_key = f"domain=\"{self.param('Domain')}\""
        msg, items = self.fofa_client.get_json_data(source_key)
        if items is None:
            self.log_error(f"调用FOFA失败: {msg}", f"Call FOFA failed : {msg}")
            return False

        self.fofa_client.store_query_result(items, project_id=self.project_id, source={})
        self.log_info(f"更新 {len(items)} 条数据.", f"Update {len(items)} data.")
        return True
