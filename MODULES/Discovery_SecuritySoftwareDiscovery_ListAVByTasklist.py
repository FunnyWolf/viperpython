# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import re

from Lib.ModuleAPI import *
from MODULES_DATA.Discovery_SecuritySoftwareDiscovery_ListAVByTasklist.avlist import avList_zh, avList_en


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
    AUTHOR = ["Viper"]

    REQUIRE_SESSION = False
    OPTIONS = register_options([
        OptionText(name='tasklist',
                   tag_zh="tasklist /svc命令结果", desc_zh="tasklist /svc命令结果",
                   tag_en="tasklist /svc result", desc_en="tasklist /svc result",
                   required=True,
                   ),
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
            for avtask in avList_zh:
                if f"{onetask}.exe".lower() == avtask.lower():
                    findav = True
                    avname_zh = avList_zh.get(avtask)
                    avname_en = avList_en.get(avtask)
                    self.log_good(f"杀毒软件: {avtask} => {avname_zh}",
                                  f"Antivirus: {avtask} => {avname_en}")
        if not findav:
            self.log_info("未发现杀毒软件.", "No antivirus software found")
        self.log_info("模块执行完成", "Module operation completed")
