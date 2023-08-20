# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import ipaddress as ipaddr
import json
import re

from Lib.ModuleAPI import *
from MODULES_DATA.Discovery_SecuritySoftwareDiscovery_ListAVByTasklist.avlist import avList_zh, avList_en


class PostModule(PostMSFRawModule):
    NAME_ZH = "主机基础信息"

    DESC_ZH = "此模块可一次性收集主机的<主机名><操作系统><域名称><进程信息><网络连接><ARP信息><网卡信息>等.\n" \
              "此模块不提供格式化输出."

    NAME_EN = "Basic host information"
    DESC_EN = "This module can collect the host's <hostname><operating system><domain name><process information><network connection><ARP information><network card information>, etc. at one time.\n" \
              "This module does not provide formatted output."

    REQUIRE_SESSION = True
    MODULETYPE = TAG2TYPE.internal

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "multi/gather/base_info"

    def check(self):
        return True, None

    def callback(self, status, message, data):
        # 调用父类函数存储结果(必须调用)
        if status:
            listen_address = []  # 本地监听的连接
            private_ipaddress = []  # 内网ip地址
            public_ipaddress = []  # 外网ip地址
            other_ipaddress = []
            arp_ipaddress = []
            interface_ipaddress = []
            useful_processes = []
            netstat_after_filter = []
            # 分析可用的网络连接
            netstat = data.get("NETSTAT")
            for one in netstat:
                if one.get("protocol") == "tcp6" or one.get("protocol") == "udp6" or one.get("protocol") == "udp":
                    continue
                netstat_after_filter.append(one)
                if one.get("state") == "LISTEN":
                    listen_address.append(one)
                elif one.get("state") != "":
                    remote_addr = one.get("remote_addr")
                    try:
                        ip = remote_addr.split(":")[0]
                        if ipaddr.ip_address(ip).is_private:
                            if ipaddr.ip_address(ip).is_loopback or ipaddr.ip_address(ip).is_unspecified:
                                pass
                            else:
                                private_ipaddress.append(one)
                        else:
                            if ipaddr.ip_address(ip).is_loopback or ipaddr.ip_address(ip).is_unspecified:
                                pass
                            else:
                                public_ipaddress.append(one)
                    except Exception as E:
                        print(E)
                else:
                    other_ipaddress.append(one)

            # 分析可用的arp信息
            arp = data.get("ARP")
            for one in arp:
                ip_addr = one.get("ip_addr")
                try:
                    if ipaddr.ip_address(ip_addr).is_reserved or \
                            ipaddr.ip_address(ip_addr).is_multicast or \
                            ipaddr.ip_address(ip_addr).is_loopback or \
                            ipaddr.ip_address(ip_addr).is_link_local or \
                            ipaddr.ip_address(ip_addr).is_unspecified:
                        continue
                    else:
                        arp_ipaddress.append(one)
                except Exception as E:
                    print(E)

            # 分析可用的网卡信息
            interface = data.get("INTERFACE")
            for one in interface:
                if isinstance(one.get("IPv4"), list):
                    interface_ipaddress.extend(one.get("IPv4"))

            # 分析可用的进程信息
            key_list = [
                {"re": "lsass*",
                 "tag_zh": "Windows", "desc_zh": "本地凭证存储进程", "tag_en": "Windows",
                 "desc_en": "Local credential store process"},
                {"re": "AnyDesk*",
                 "tag_zh": "CC", "desc_zh": "AnyDesk远程控制工具",
                 "tag_en": "CC", "desc_en": "Anydesk remote control tool"},
                {"re": "tv_*",
                 "tag_zh": "CC", "desc_zh": "TeamViewer远程控制工具",
                 "tag_en": "CC", "desc_en": "TeamViewer remote control tool"},

            ]
            for key in avList_zh:
                key_list.append({"re": key,
                                 "tag_zh": "AV", "desc_zh": avList_zh.get(key),
                                 "tag_en": "AV", "desc_en": avList_en.get(key)})

            for one_key in key_list:
                pattern = re.compile(one_key.get("re"))
                one_key['pattern'] = pattern
            processes = data.get("PROCESSES")
            for process in processes:
                name = process.get("name")
                for one_key in key_list:
                    if one_key['pattern'].search(name) is not None:
                        useful_processes.append(
                            {"tag_zh": one_key.get("tag_zh"), "desc_zh": one_key.get("desc_zh"),
                             "tag_en": one_key.get("tag_en"), "desc_en": one_key.get("desc_en"), "process": process})
                        break

            data["NETSTAT"] = netstat_after_filter
            data["ARP"] = arp_ipaddress
            data["private_ipaddress"] = private_ipaddress
            data["public_ipaddress"] = public_ipaddress
            data["listen_address"] = listen_address
            data["interface_ipaddress"] = interface_ipaddress
            data["useful_processes"] = useful_processes
            self.log_store(json.dumps(data))
        else:
            print(message)
