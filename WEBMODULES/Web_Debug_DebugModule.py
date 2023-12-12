# -*- coding: utf-8 -*-
# @File  : PostMulitMsfBypassUAC.py
# @Date  : 2019/3/15
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(WebPythonModule):
    NAME_ZH = "测试调试模块"
    DESC_ZH = "测试调试模块"

    NAME_EN = "Test Debug Module"
    DESC_EN = "Test Debug Module"
    MODULETYPE = TAG2TYPE.Web_PortService_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionInt(name='TIMEOUT',
                  tag_zh="请求超时时间", desc_zh="每个Request请求超时时间(秒)",
                  tag_en="Request Timeout", desc_en="Every http request timeout (seconds)",
                  default=1),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

        # 参数初始化

    def check(self):
        """执行前的检查函数"""
        return True, ""

    def run(self):
        import time
        self.log_info("111", "222")
        self.log_raw("111")
        self.log_good("111", "222")
        self.log_warn("111", "222")
        self.log_error("111", "222")
        self.log_except("111", "222")
        a = []
        a.append({"ip": "10.10.10.10", 'port': 80})
        a.append({"ip": "10.10.10.10", 'port': 443})
        self.log_table(a, a)
        for i in range(self.param("TIMEOUT")):
            time.sleep(1)
            self.log_info(int(time.time()), "222")
        return "this is result"
