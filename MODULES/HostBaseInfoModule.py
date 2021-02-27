# -*- coding: utf-8 -*-
# @File  : SimpleRewMsfModule.py
# @Date  : 2019/1/11
# @Desc  :


import json
import re

import ipaddr

from Lib.ModuleAPI import *
from MODULES_DATA.HostBaseInfoModule.avjson import av_dict


class PostModule(PostMSFRawModule):
    NAME = "主机基础信息"
    DESC = "此模块可一次性收集主机的<主机名><操作系统><域名称><进程信息><网络连接><ARP信息><网卡信息>等.\n" \
           "请注意,此模块不提供格式化输出."
    REQUIRE_SESSION = True
    MODULETYPE = TAG2CH.internal

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
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
                        if ipaddr.IPAddress(ip).is_private:
                            private_ipaddress.append(one)
                        else:
                            if ipaddr.IPAddress(ip).is_loopback or ipaddr.IPAddress(ip).is_unspecified:
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
                if ipaddr.IPAddress(ip_addr).is_reserved or ipaddr.IPAddress(ip_addr).is_multicast or ipaddr.IPAddress(
                        ip_addr).is_loopback or ipaddr.IPAddress(ip_addr).is_link_local or ipaddr.IPAddress(
                    ip_addr).is_unspecified:
                    continue
                else:
                    arp_ipaddress.append(one)
            # 分析可用的网卡信息
            interface = data.get("INTERFACE")
            for one in interface:
                if isinstance(one.get("IPv4"), list):
                    interface_ipaddress.extend(one.get("IPv4"))

            # 分析可用的进程信息
            key_list = [
                {"re": "lsass*", "tag": "Windows", "desc": "本地凭证存储进程"},
                # {"re": "360*","tag":"AV","desc":"360杀毒相关进程"},
                # {"re": "ZhuDongFangYu*", "tag": "AV", "desc": "360主动防御进程"},
                {"re": "AnyDesk*", "tag": "CC", "desc": "AnyDesk远程控制工具"},
                {"re": "tv_*", "tag": "CC", "desc": "TeamViewer远程控制工具"},

            ]
            for key in av_dict:
                key_list.append({"re": key, "tag": "AV", "desc": av_dict.get(key)})

            processes = data.get("PROCESSES")
            for process in processes:
                name = process.get("name")
                for one_key in key_list:
                    if re.search(one_key.get("re"), name) is not None:
                        useful_processes.append(
                            {"tag": one_key.get("tag"), "desc": one_key.get("desc"), "process": process})
                        break

            data["NETSTAT"] = netstat_after_filter
            data["ARP"] = arp_ipaddress
            data["private_ipaddress"] = private_ipaddress
            data["public_ipaddress"] = public_ipaddress
            data["listen_address"] = listen_address
            data["interface_ipaddress"] = interface_ipaddress
            data["useful_processes"] = useful_processes
            self.store_log(json.dumps(data))
        else:
            print(message)
