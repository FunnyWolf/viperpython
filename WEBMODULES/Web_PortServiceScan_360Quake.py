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
        if self.quake_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
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
        items_total = []
        for oneip in ip_list:
            source_key = f"ip:\"{oneip}\""
            msg, items = self.quake_client.get_json_data(source_key)
            if items is None:
                Notice.send_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
                continue
            items_total.extend(items)
        self.log_info(f'更新了{len(items_total)}条数据', f'Updated {len(items_total)} pieces of data')
        DataStore.quake_result(items_total, project_id=self.project_id, source={})