# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "nmap端口扫描"
    DESC_ZH = "调用nmap端口扫描"

    NAME_EN = "nmap port scan"
    DESC_EN = "Call nmap port scan"
    MODULETYPE = TAG2TYPE.Web_Network_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='ipdomain',
                  tag_zh="ipdomain",
                  desc_zh="ipdomain",
                  tag_en="ipdomain",
                  desc_en="ipdomain"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):
        dataset = DataSet()
        targets = []
        for one_input in self.input_list:
            targets.append({'ipdomain': one_input.get('ipdomain')})
        ipdomain = self.param("ipdomain")
        targets.append({'ipdomain': ipdomain})

        nmapapi_obj = NmapAPI()
        dataset = nmapapi_obj.scan(targets=targets, dataset=dataset)

        self.log_info("存储数据到数据库", "Save data to database")
        dataset.set_project_id(self.project_id)
        dataset.save_to_db()
