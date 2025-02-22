# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :

import json

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "异步Netbios扫描"
    DESC_ZH = "基于nextnet的内网异步netbios扫描.\n" \
              "模块扫描子网开放netbios协议(137端口)的主机,并获取主机的网卡地址.\n" \
              "主要用于在拥有多个网段的内网中寻找目标."

    NAME_EN = "Asynchronous Netbios scan"
    DESC_EN = "Asynchronous netbios scanning of intranet based on nextnet.\n" \
              "The module scans the host whose subnet opens the netbios protocol (port 137) and obtains the host's network card address.\n" \
              "It is mainly used to find a target in an intranet with multiple network segments."

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1560"]  # ATTCK向量
    REFERENCES = ["https://attack.mitre.org/techniques/T1560/003/", "https://github.com/hdm/nextnet"]
    README = ["https://www.yuque.com/vipersec/module/dtmof0"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionStr(name='IPADDRESS',
                  tag_zh="子网网段", desc_zh="支持192.168.146.1/24类型输入",
                  tag_en="Subnet", desc_en="Support 192.168.146.1/24 type input",
                  length=24,
                  ),
        OptionInt(name='TIMEOUT',
                  tag_zh="超时时间", desc_zh="扫描超时时间(秒)",
                  tag_en="Timeout", desc_en="Scan timeout (seconds)",
                  default=60 * 10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/manage/upload_and_exec_api"
        self.outfile = None

    def check(self):
        """执行前的检查函数"""
        session = Session(self._sessionid)

        if session.is_windows:
            self.set_msf_option("LPATH", "nextnet.exe")
            self.set_msf_option("RPATH", "nextnet_viper.exe")
        elif session.is_linux:
            self.set_msf_option("LPATH", "nextnet")
            self.set_msf_option("RPATH", "nextnet_viper")
        else:
            return False, "模块只支持Windows/Linux meterpreter类型Session", "The module only supports Windows/Linux meterpreter type Session"

        ipaddress = self.param("IPADDRESS")
        args = f"{ipaddress}"
        self.set_msf_option("ARGS", args)

        self.set_msf_option("CLEANUP", True)
        self.set_msf_option("TIMEOUT", self.param("TIMEOUT"))

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        data_zh = []
        data_en = []
        for oneline in data.split("\n"):
            try:
                one_result = json.loads(oneline)
                ipaddress = one_result.get('host')
                data_zh.append(
                    {"IP": ipaddress, "Host": one_result.get('name'), "Info": str(one_result.get('info')),
                     "Nets": str(one_result.get('nets'))})
                data_en.append(
                    {"IP": ipaddress, "Host": one_result.get('name'), "Info": str(one_result.get('info')),
                     "Nets": str(one_result.get('nets'))})

                self.add_host(ipaddress,
                              source=self.host_ipaddress,
                              linktype="scan",
                              data={"method": "netbiosscan"})

                HostInfo.update_info(ipaddress, one_result)

                tmpBanner = {"other": {"Host": one_result.get('name'), "Nets": one_result.get('nets'),
                                       "Info": one_result.get('info')}}
                tmpService = "netbios_udp"
                self.add_portservice(ipaddress=ipaddress,
                                     port=int(one_result.get('port')),
                                     banner=tmpBanner,
                                     service=tmpService)
            except Exception as E:
                self.log_warning(oneline)
                self.log_except(E, E)

        self.log_table(data_zh, data_en)
        self.log_raw("\n\n")
        self.log_good("原始输出:", "Raw output:")
        self.log_raw(data)
