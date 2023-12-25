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
        domain_list = []
        for one_input in self.input_list:
            ipdomain = one_input.get("ipdomain")
            if api.is_domain(ipdomain):
                domain_list.append(ipdomain)
        domain_list.append(self.param("Domain"))
        total_items = []
        for domain in domain_list:
            source_key = f"domain:\"{domain}\""
            msg, items = self.quake_client.get_json_data(source_key)
            if items is None:
                Notice.send_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
                continue
            total_items.extend(items)
        DataStore.quake_result(total_items, project_id=self.project_id, source={})
        self.log_info(f'更新了{len(total_items)}条数据', f'Updated {len(total_items)} pieces of data')
        return True
