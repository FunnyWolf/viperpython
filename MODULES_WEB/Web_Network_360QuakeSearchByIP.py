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
    MODULETYPE = TAG2TYPE.Web_Network_Scan
    README = [""]
    REFERENCES = [""]
    AUTHOR = ["Viper"]
    OPTIONS = register_options([
        OptionStr(name='IP',
                  tag_zh="IP地址",
                  desc_zh="IP地址 e.g.(192.168.1.1/24,192.168.1.1-255,192.168.1.1)",
                  tag_en="IP",
                  desc_en="IP e.g.(192.168.1.1/24,192.168.1.1-255,192.168.1.1)"),
    ])

    def __init__(self, project_id, input_list: list, custom_param):
        super().__init__(project_id, input_list, custom_param)

        # 参数初始化
        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        self.quake_client.init_conf_from_cache()
        try:
            if self.param("ip") is not None:
                str_to_ips(self.param("ip"))
        except Exception as E:
            return False, "IP地址格式错误", "IP address format error"
        return True, ""

    def run(self):

        ip_list = []
        if self.param("IP") is not None:
            ip_list.extend(str_to_ips(self.param("IP")))

        for one_input in self.input_list:
            ip = one_input.get("ip")
            ip_list.append(ip)
            ipdomain = one_input.get("ipdomain")
            ip_list.append(ipdomain)

        dataset = DataSet()
        for oneip in ip_list:
            source_key = f"ip:\"{oneip}\""
            flag = self.quake_client.search_by_query_str(source_key, dataset)
            self.log_info(f"Quake Search : {source_key} Count: {flag}")

        self.log_info("存储数据到数据库", "Save data to database")
        dataset.set_project_id(self.project_id)
        dataset.save_to_db()
