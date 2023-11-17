# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "360 Quake端口扫描"
    DESC_ZH = "调用360 Quake进行端口扫描"

    NAME_EN = "360 Quake port scan"
    DESC_EN = "Call 360 Quake to perform port scan"
    MODULETYPE = TAG2TYPE.Web_PortService_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

        # 参数初始化
        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        if self.quake_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        for one_input in self.input_list:
            ipdomain = one_input.get("ipdomain")
            source_key = f"ip:\"{ipdomain}\""
            msg, items = self.quake_client.get_json_data(source_key)

            if items is None:
                Notice.send_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
                return False

            self.quake_client.store_query_result(items, project_id=self.project_id, source={})
