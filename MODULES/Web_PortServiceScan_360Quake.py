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
                  tag_zh="IP",
                  desc_zh="IP",
                  tag_en="IP",
                  desc_en="IP"),
        OptionInt(name='MaxSize',
                  tag_zh="最大数量",
                  desc_zh="最大数量",
                  tag_en="MaxSize",
                  desc_en="MaxSize",
                  default=1000),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.quake_client = Quake()

    def check(self):
        """执行前的检查函数"""
        if self.param("MaxSize") > 1000:
            return False, "MaxSize不能大于1000", "MaxSize cannot be greater than 1000"
        elif self.param("MaxSize") < 0:
            return False, "MaxSize不能小于0", "MaxSize cannot be less than 0"

        if self.quake_client.init_conf_from_cache() is not True:
            return False, "Quake 配置无效", "Quake configuration invalid"
        return True, ""

    def run(self):
        self.log_info(f"IP: {self.param('IP')}", f"IP: {self.param('IP')}")

        source_key = f"ip:\"{self.param('IP')}\""
        msg, items = self.quake_client.get_json_data(source_key, size=self.param('MaxSize'))

        if items is None:
            self.log_error(f"调用Quake失败: {msg}", f"Call Quake failed : {msg}")
            return False

        self.quake_client.store_query_result(items, source_key=source_key)
        self.log_info(f"更新 {len(items)} 条数据.", f"Update {len(items)} data.")
        return True
