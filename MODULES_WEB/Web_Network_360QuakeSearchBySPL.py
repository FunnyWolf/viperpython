# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "360 Quake搜索语句执行"
    DESC_ZH = "调用360 Quake 执行用户输入的搜索语句"

    NAME_EN = "360 Quake search statement execution"
    DESC_EN = "Call 360 Quake to execute the search statement entered by the user"
    MODULETYPE = TAG2TYPE.Web_Network_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='SearchStr',
                  tag_zh="搜索语句",
                  desc_zh="搜索语句",
                  tag_en="Search String",
                  desc_en="Search String"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        self.quake_client.init_conf_from_cache()
        return True, ""

    def run(self):
        dataset = DataSet()
        source_key = self.param('SearchStr')
        flag = self.quake_client.search_by_query_str(source_key, dataset)
        self.log_info(f"Quake Search : {source_key} Count: {flag}")
        self.log_info("存储数据到数据库", "Save data to database")
        dataset.set_project_id(self.project_id)
        dataset.save_to_db()
        return True
