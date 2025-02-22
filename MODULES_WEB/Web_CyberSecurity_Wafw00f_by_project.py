# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *
from WebDatabase.documents import ServiceDocument


class PostModule(WebPythonModule):
    NAME_ZH = "wafw00f WAF识别 (当前项目)"
    DESC_ZH = "调用wafw00f对当前项目所有web网站进行WAF识别"

    NAME_EN = "wafw00f WAF recognition (Default Project)"
    DESC_EN = "Call wafw00f for WAF recognition"
    MODULETYPE = TAG2TYPE.Web_CyberSecurity_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):
        urls = []

        servicemodels = []
        servicemodels.extend(Service.list_by_project_and_service(project_id=self.project_id, service="http"))
        servicemodels.extend(Service.list_by_project_and_service(project_id=self.project_id, service="https"))
        for one_model in servicemodels:
            obj = ServiceDocument()
            obj.ipdomain = one_model.get("ipdomain")
            obj.port = one_model.get("port")
            obj.service = one_model.get("service")
            url = obj.group_url()
            if url:
                urls.append(url)

        dataset = DataSet()
        WafCheck.scan(urls=urls, dataset=dataset)

        dataset.set_project_id(self.project_id)
        self.log_info("存储数据到数据库", "Save data to database")
        dataset.save_to_db()
