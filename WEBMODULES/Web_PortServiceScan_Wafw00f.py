# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :
import Lib.api
from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "wafw00f WAF识别"
    DESC_ZH = "调用wafw00f进行WAF识别"

    NAME_EN = "wafw00f WAF recognition"
    DESC_EN = "Call wafw00f for WAF recognition"
    MODULETYPE = TAG2TYPE.Web_PortService_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='URL',
                  tag_zh="URL",
                  desc_zh="URL",
                  tag_en="URL",
                  desc_en="URL"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):
        wait_list = []
        for one_input in self.input_list:
            url = self.group_url_by_ipdomain_record(one_input)
            if url:
                wait_list.append({'ipdomain': one_input.get('ipdomain'), 'port': one_input.get('port'), "url": url})

        url = self.param("URL")
        if url is not None:
            pret = Lib.api.urlParser(url)
            if pret is None:
                self.log_warn("输入的URL无效", "Invalid URL")
            else:
                hostname, port, path, query, ssl = pret
                wait_list.append({'ipdomain': hostname, 'port': port, "url": url})

        for one_task in wait_list:
            result = WafCheck.check_url(one_task.get("url"))
            if result:
                DataStore.wafcheck_result(result, ipdomain=one_task.get("ipdomain"), port=one_task.get("port"),
                                          project_id=self.project_id,
                                          source={})
                self.log_info(
                    f'IPDomain: {one_task.get("ipdomain")} Port:{one_task.get("port")} Detect: {result.get("detected")}',
                    f'IPDomain: {one_task.get("ipdomain")} Port:{one_task.get("port")} Detect: {result.get("detected")}')

        # items = WafCheck.check(url_list)
        # self.log_info(f'更新{len(items)}条数据', f'Updated {len(items)} pieces of data')
