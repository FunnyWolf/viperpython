# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME = "腾讯API网关C2隐藏"
    DESC = "模块会根据现有的监听配置及用户输入的API网关自动生成一个虚拟监听,用户可以使用该虚拟监听直接生成exe来进行上线"
    MODULETYPE = TAG2CH.Resource_Development

    ATTCK = ["T1583.006"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/lekesi"]
    REFERENCES = ["https://www.yuque.com/vipersec/blog/lb8f2m",
                  "https://console.cloud.tencent.com/apigateway/service?rid=1"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionHander(),
        OptionStr(name='apiserver', name_tag="API网关公网域名", required=True, desc="填写API网关的公网域名"),
        OptionStr(name='apiip', name_tag="API网关公网IP地址", required=True, desc="使用IP地址上线时填写此信息"),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        handler_config = self.get_handler_config()
        # 检查
        payload = handler_config.get("PAYLOAD")
        if "meterpreter_reverse_https" not in payload:
            return False, "只支持meterpreter_reverse_https类型监听"
        handlerid = handler_config.get("ID")
        if handlerid < 0:
            return False, "必须使用真实监听"
        return True, None

    def run(self):
        handler_config = self.get_handler_config()
        pass
