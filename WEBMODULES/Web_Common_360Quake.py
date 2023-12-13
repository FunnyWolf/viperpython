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
    MODULETYPE = TAG2TYPE.Web_Common_Module
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
        if self.quake_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        source_key = self.param('SearchStr')
        msg, items = self.quake_client.get_json_data(source_key)
        if items is None:
            Notice.send_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
            return False
        DataStore.quake_result(items, project_id=self.project_id, source={})
        self.log_info(f'更新了{len(items)}条数据', f'Updated {len(items)} pieces of data')
        return True
