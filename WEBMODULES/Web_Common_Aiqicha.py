# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "爱企查搜索企业备案/微信公众号/App信息"
    DESC_ZH = "爱企查搜索企业备案/微信公众号/App信息"

    NAME_EN = "Aiqicha search company ICP/Wechat/App"
    DESC_EN = "Aiqicha search company ICP/Wechat/App"
    MODULETYPE = TAG2TYPE.Web_Common_Module
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

        self.aiqicha_client = None

    def check(self):
        """执行前的检查函数"""
        if self.aiqicha_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        source_key = self.param('SearchStr')
        msg, items = self.aiqicha_client.get_json_data(source_key)
        if items is None:
            Notice.send_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
            return False
        DataStore.quake_result(items, project_id=self.project_id, source={})
        self.log_info(f'更新了{len(items)}条数据', f'Updated {len(items)} pieces of data')
        return True
