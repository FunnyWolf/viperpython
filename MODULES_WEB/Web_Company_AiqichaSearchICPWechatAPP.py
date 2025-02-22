# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "爱企查搜索备案/公众号/App信息"
    DESC_ZH = "爱企查搜索备案/公众号/App信息"

    NAME_EN = "Aiqicha search company ICP/Wechat/App"
    DESC_EN = "Aiqicha search company ICP/Wechat/App"
    MODULETYPE = TAG2TYPE.Web_Company_Intelligence
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='company_name',
                  tag_zh="公司名称",
                  desc_zh="公司名称",
                  tag_en="Company Name",
                  desc_en="Company Name"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

        self.aiqicha_client = Aiqicha()

    def check(self):
        """执行前的检查函数"""
        if self.aiqicha_client.init_conf_from_cache() is not True:
            return False, "爱企查 配置无效", "Aiqicha configuration invalid"
        return True, ""

    def run(self):
        company_name = self.param('company_name')
        dataset = DataSet()
        self.aiqicha_client.search_by_name(company_name, dataset)
        dataset.set_project_id(self.project_id)
        self.log_info("存储数据到数据库", "Save data to database")
        dataset.save_to_db()
        return True
