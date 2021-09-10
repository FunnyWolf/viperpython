# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import re

from Lib.ModuleAPI import *
from MODULES_DATA.Discovery_SecuritySoftwareDiscovery_ListAVByTasklist.avlist import avList


class PostModule(PostPythonModule):
    NAME_ZH = "查找杀毒软件进程"
    DESC_ZH = "模块通过将 tasklist /svc 与已知数据对比,获取系统已安装杀毒软件信息.\n" \
              "通过webshell命令执行功能执行 tasklist /svc ,然后将结果拷贝到输入框运行即可"

    NAME_EN = "Find antivirus software process"
    DESC_EN = "The module obtains information about the anti-virus software installed in the system by comparing `tasklist /svc` output with known data.\n" \
              "Execute tasklist /svc through the webshell command execution function, and then copy the result to the input box to run"
    MODULETYPE = TAG2TYPE.Discovery

    ATTCK = ["T1585"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/nhzbv6"]
    REFERENCES = ["https://github.com/gh0stkey/avList",
                  "https://attack.mitre.org/techniques/T1518/001/"]
    AUTHOR = "Viper"

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionText(name='tasklist', name_tag="tasklist /svc命令结果", required=True, desc="tasklist /svc命令结果"),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)

    def check(self):
        """执行前的检查函数"""
        return True, None

    def run(self):
        findav = False
        data = self.param("tasklist")
        pattern = re.compile(r"(.*?)\.exe")  # 查找数字
        tasklist = pattern.findall(data)
        for onetask in tasklist:
            for avtask in avList:
                if f"{onetask}.exe".lower() == avtask.lower():
                    findav = True
                    avname = avList.get(avtask)
                    self.log_warning(f"发现杀毒软件: {avtask} => {avname}")
        if not findav:
            self.log_info("未发现杀毒软件.")
        self.log_info("模块运行完成.")
