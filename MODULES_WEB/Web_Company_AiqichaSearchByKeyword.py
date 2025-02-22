# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


# 只支持suggest cookie
class PostModule(WebPythonModule):
    NAME_ZH = "爱企查关键字搜索"
    DESC_ZH = "调用爱企查,通过关键字搜索企业名称"

    NAME_EN = "Aiqicha keyword search"
    DESC_EN = "Call Aiqicha to search company name by keyword"
    MODULETYPE = TAG2TYPE.Web_Company_Intelligence
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='keyword',
                  tag_zh="关键字",
                  desc_zh="输入的关键字,比如搜索腾讯相关的公司,则输入'腾讯'",
                  tag_en="keyword",
                  desc_en="The keyword you input, such as '腾讯'"),
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
        keyword = self.param('keyword')
        result = self.aiqicha_client.suggest_by_keyword(keyword)
        if result:
            self.log_good("爱企查搜索结果:", "Aiqicha search result:")
            for one_suggest in result:
                result_str: str = one_suggest.get('resultStr')
                result_str = result_str.replace("<em>", "")
                result_str = result_str.replace("</em>", "")
                self.log_info(result_str, result_str)
        else:
            self.log_error(f"未搜索到结果", f"No results found")
        return True
