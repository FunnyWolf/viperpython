# -*- coding: utf-8 -*-
# @File  : ipfilter.py
# @Date  : 2021/10/30
# @Desc  :
import ipaddress
import os

from django.conf import settings

# from Lib.External.qqwry import qqwry
from Lib.api import data_return
from Lib.configs import CODE_MSG_ZH, CODE_MSG_EN, IPFilter_MSG_EN, IPFilter_MSG_ZH
from Lib.ipgeo import IPGeo
from Lib.notice import Notice
from Lib.xcache import Xcache


class IPFilter(object):

    def __init__(self):
        pass

    @staticmethod
    def list(ip):
        if ip is None:
            result = {}
            result["switch"] = Xcache.get_ipfilter_switch_cache()
            result["cloud_blacklist"] = Xcache.get_ipfilter_cloud_blacklist_cache()
            result["sandbox_blacklist"] = Xcache.get_ipfilter_sandbox_blacklist_cache()
            result["geo_blacklist"] = Xcache.get_ipfilter_geo_blacklist_cache()
            result["diy_whitelist"] = "\n".join(IPFilter.get_diy_whitelist())
            result["diy_blacklist"] = "\n".join(IPFilter.get_diy_blacklist())
            context = data_return(200, result, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return context
        else:
            flag, zh_content, en_content = IPFilter.is_allow_for_check(ip)
            if flag:
                context = data_return(202, True, zh_content, en_content)
            else:
                context = data_return(302, True, zh_content, en_content)
            return context

    @staticmethod
    def update(data):
        Xcache.set_ipfilter_switch_cache(data.get("switch"))
        Xcache.set_ipfilter_cloud_blacklist_cache(data.get("cloud_blacklist"))
        Xcache.set_ipfilter_sandbox_blacklist_cache(data.get("sandbox_blacklist"))
        Xcache.set_ipfilter_geo_blacklist_cache(data.get("geo_blacklist"))
        IPFilter.update_diy_whitelist(data.get("diy_whitelist").split("\n"))
        IPFilter.update_diy_blacklist(data.get("diy_blacklist").split("\n"))
        context = data_return(201, None, IPFilter_MSG_ZH.get(201), IPFilter_MSG_EN.get(201))
        return context

    @staticmethod
    def is_allow(ip):
        geo_str_zh = IPGeo.get_ip_geo_str(ip, "zh-CN")
        geo_str_en = IPGeo.get_ip_geo_str(ip, "en-US")
        Notice.send_info(f"[新Session连接] [{geo_str_zh}] {ip}", f"[New Session Connection] [{geo_str_en}] {ip}")
        # 总开关检查
        if Xcache.get_ipfilter_switch_cache() is not True:
            return True

        # ip有效性检查
        try:
            ipaddress.IPv4Address(ip)
        except Exception as E:
            Notice.send_error(f"[非IPv4地址] [放行] {ip}", f"[Not IPv4 Address] [Pass] {ip}")
            return True

        # 查询geo信息
        geo_list = IPGeo.get_ip_geo(ip, "zh-CN")

        # 自定义白名单
        if IPFilter.in_diy_whitelist(ip):
            Notice.send_info(f"[自定义白名单] [放行] {ip}", f"[Custom whitelist] [Pass] {ip}")
            return True

        # 自定义黑名单
        if IPFilter.in_diy_blacklist(ip):
            Notice.send_warning(f"[自定义黑名单] [屏蔽] {ip}", f"[Custom blacklist] [Block] {ip}")
            return False

        # 沙箱黑名单
        if IPFilter.in_sandbox_blacklist(ip):
            Notice.send_warning(f"[屏蔽沙箱IP] [屏蔽] {ip}", f"[Sandbox blacklist] [Block] {ip}")
            return False

        # 云主机黑名单
        if IPFilter.in_cloud_blacklist(geo_list):
            Notice.send_warning(f"[屏蔽云厂商IP] [屏蔽] {ip}", f"[Cloud blacklist] [Block] {ip}")
            return False

        # geo 黑名单
        if IPFilter.in_geo_blacklist(geo_list):
            Notice.send_warning(f"[地理位置黑名单] [屏蔽] {ip}", f"[Geographic Blacklist] [Block] {ip}")
            return False

        # reuslt = geoip2_instance.get_geo(ip)
        # print(reuslt)
        # reuslt = ip2region_instance.get_geo(ip)
        # print(reuslt)

        # reuslt = qqwry.get_location(ip)
        # print(reuslt)
        # 最终返回
        Notice.send_info(f"[检查结束] [放行] {ip}", f"[Check finish] [Pass] {ip}")
        return True

    @staticmethod
    def is_allow_for_check(ip):
        # 总开关检查
        if Xcache.get_ipfilter_switch_cache() is not True:
            return True, f"[防火墙关闭] [放行] {ip}", f"[Firewall close] [Pass] {ip}"

        # ip有效性检查
        try:
            ipaddress.IPv4Address(ip)
        except Exception as E:
            return True, f"[非IPv4地址] [放行] {ip}", f"[Not IPv4 Address] [Pass] {ip}"

        # 查询geo信息
        geo_list = IPGeo.get_ip_geo(ip, "zh-CN")

        # 自定义白名单
        if IPFilter.in_diy_whitelist(ip):
            return True, f"[自定义白名单] [放行] {ip}", f"[Custom whitelist] [Pass] {ip}"

        # 自定义黑名单
        if IPFilter.in_diy_blacklist(ip):
            return False, f"[自定义黑名单] [屏蔽] {ip}", f"[Custom blacklist] [Block] {ip}"

        # 沙箱黑名单
        if IPFilter.in_sandbox_blacklist(ip):
            return False, f"[屏蔽沙箱IP] [屏蔽] {ip}", f"[Sandbox blacklist] [Block] {ip}"

        # 云主机黑名单
        if IPFilter.in_cloud_blacklist(geo_list):
            return False, f"[屏蔽云厂商IP] [屏蔽] {ip}", f"[Cloud blacklist] [Block] {ip}"

        # geo 黑名单
        if IPFilter.in_geo_blacklist(geo_list):
            return False, f"[地理位置黑名单] [屏蔽] {ip}", f"[Geographic Blacklist] [Block] {ip}"

        # reuslt = geoip2_instance.get_geo(ip)
        # print(reuslt)
        # reuslt = ip2region_instance.get_geo(ip)
        # print(reuslt)
        # reuslt = qqwry.get_location(ip)
        # print(reuslt)
        # 最终返回
        return True, f"[检查结束] [放行] {ip}", f"[Check finish] [Pass] {ip}"

    # 自定义白名单获取
    @staticmethod
    def get_diy_whitelist():
        subnet_list = []
        network_list = Xcache.get_ipfilter_diy_whitelist_cache()
        for onenetwork in network_list:
            subnet_list.append(str(onenetwork))
        return subnet_list

    # 自定义白名单更新
    @staticmethod
    def update_diy_whitelist(subnet_list):
        network_list = []
        for subnet in subnet_list:
            try:
                onenetwork = ipaddress.IPv4Network(subnet, strict=False)
            except Exception as E:
                continue
            network_list.append(onenetwork)
        Xcache.set_ipfilter_diy_whitelist_cache(network_list)

    # 自定义白名单检查
    @staticmethod
    def in_diy_whitelist(ip):
        ipnetwork = ipaddress.IPv4Network(ip, strict=False)
        network_list = Xcache.get_ipfilter_diy_whitelist_cache()
        for onenetwork in network_list:
            if ipnetwork.subnet_of(onenetwork):
                return True
        else:
            return False

    # 自定义黑名单获取
    @staticmethod
    def get_diy_blacklist():
        subnet_list = []
        network_list = Xcache.get_ipfilter_diy_blacklist_cache()
        for onenetwork in network_list:
            subnet_list.append(str(onenetwork))
        return subnet_list

    # 自定义黑名单更新
    @staticmethod
    def update_diy_blacklist(subnet_list):
        network_list = []
        for subnet in subnet_list:
            try:
                onenetwork = ipaddress.IPv4Network(subnet, strict=False)
            except Exception as E:
                continue
            network_list.append(onenetwork)
        Xcache.set_ipfilter_diy_blacklist_cache(network_list)

    # 自定义黑名单检查
    @staticmethod
    def in_diy_blacklist(ip):
        ipnetwork = ipaddress.IPv4Network(ip, strict=False)
        network_list = Xcache.get_ipfilter_diy_blacklist_cache()
        for onenetwork in network_list:
            if ipnetwork.subnet_of(onenetwork):
                return True
        else:
            return False

    # 云厂商黑名单获取

    # 云厂商黑名单更新

    # 云厂商黑名单检查
    @staticmethod
    def in_cloud_blacklist(geo_list):
        if Xcache.get_ipfilter_cloud_blacklist_cache():
            if geo_list[3] in ["移动", "联通", "电信"]:
                return False
            else:
                return True
        else:
            return False

    # 沙箱黑名单获取

    # 沙箱黑名单初始化
    @staticmethod
    def init_sandbox_blacklist_data():
        network_list = []
        dbFile = os.path.join(settings.BASE_DIR, 'STATICFILES', 'STATIC', 'blackip.txt')
        with open(dbFile) as f:
            subnet_list = f.readlines()
            for subnet in subnet_list:
                subnet = subnet.strip()
                try:
                    onenetwork = ipaddress.IPv4Network(subnet, strict=False)
                except Exception as E:
                    continue
                network_list.append(onenetwork)
            Xcache.set_ipfilter_sandbox_blacklist_data_cache(network_list)
        return network_list

    # 沙箱黑名单检查
    @staticmethod
    def in_sandbox_blacklist(ip):
        if Xcache.get_ipfilter_sandbox_blacklist_cache():
            ipnetwork = ipaddress.IPv4Network(ip, strict=False)
            network_list = Xcache.get_ipfilter_sandbox_blacklist_data_cache()
            if network_list is None or len(network_list) == 0:
                network_list = IPFilter.init_sandbox_blacklist_data()

            for onenetwork in network_list:
                if ipnetwork.subnet_of(onenetwork):
                    return True
            else:
                return False
        else:
            return False

    # 沙箱黑名单获取

    # 沙箱黑名单更新

    # 沙箱黑名单检查

    # 地理位置黑名单获取
    @staticmethod
    def in_geo_blacklist(geo_list):
        geo_blacklist = Xcache.get_ipfilter_geo_blacklist_cache()
        # 检查海外
        if "海外" in geo_blacklist:
            if geo_list[0] != "中国":
                return True
        # 检查省份
        if geo_list[1] in geo_blacklist:
            return True
        else:
            return False

    # 地理位置黑名单更新

    # 地理位置黑名单检查

    # 地理位置白名单获取

    # 地理位置白名单更新

    # 地理位置白名单检查
    @staticmethod
    def in_geo_whitelist(geo_list):
        geo_whitelist = Xcache.get_ipfilter_geo_whitelist_cache()
        if len(geo_whitelist) == 0:
            return True

        # 检查海外
        if "海外" in geo_whitelist:
            if geo_list[0] != "中国":
                return True
        # 检查省份
        if geo_list[1] in geo_whitelist:
            return True
        else:
            return False
