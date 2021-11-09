# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME_ZH = "内网ARP扫描"
    DESC_ZH = "目标内网的ARP扫描,所有ARP请求与回复目标内网.\n" \
              "ARP消息只证明此主机存活,不会探测端口.\n" \
              "如其他模块需要连接发现的主机,请使用Session添加对应路由或Socks代理"

    NAME_EN = "Intranet ARP scan"
    DESC_EN = "ARP scan of the target intranet, all ARP requests and replies to the target intranet.\n" \
              "The ARP message only proves that the host is alive and will not detect the port.\n" \
              "If other modules need to connect to the discovered host, please use Session to add the corresponding route or Socks proxy"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1046"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pf9z8a"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1046/"]
    AUTHOR = ["Viper"]
    REQUIRE_SESSION = True
    OPTIONS = register_options([
        OptionIPAddressRange(name='address_range',
                             tag_zh="IP列表",
                             desc_zh="IP列表(支持1.1.1.1,2.2.2.2,3.3.3.3-3.3.3.10格式输入)",
                             tag_en="IP list",
                             desc_en="IP list (support 1.1.1.1, 2.2.2.2, 3.3.3.3-3.3.3.10 format input)",
                             required=True),
        OptionInt(name='threads',
                  tag_zh="扫描线程数", desc_zh="扫描线程数(最大值10)",
                  tag_en="Number of threads", desc_en="Number of scanning threads (maximum 10)",
                  required=True, default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.type = "post"
        self.mname = "windows/gather/arp_scanner_api"

    def check(self):
        """执行前的检查函数"""

        self.session = Session(self._sessionid)
        if self.session.is_windows is not True:
            return False, "此模块只支持Windows的Meterpreter", "This module only supports Meterpreter for Windows"

        address_range = self.param_address_range('address_range')
        if len(address_range) > 256:
            return False, "扫描IP范围过大(超过256),请缩小范围", "Scanning IP range is too large (more than 256), please reduce the range"
        elif len(address_range) < 0:
            return False, "输入的IP列表格式有误", "The format of the entered IP list is incorrect"
        self.set_msf_option('RHOSTS', ", ".join(address_range))

        threads = self.param('threads')
        # 检查port_list
        if threads <= 0 or threads > 20:
            return False, "输入的扫描线程数有误(最大值10)", "The number of scan threads entered is incorrect (maximum 10)"
        self.set_msf_option('THREADS', threads)

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
            return
        try:
            host_mac_list = data
            data_zh = []
            data_en = []
            for host_mac in host_mac_list:
                # 输出部分
                data_zh.append(
                    {"IP": host_mac.get('host'), "MAC": host_mac.get('mac'), "网卡厂商": host_mac.get('company')})
                data_en.append(
                    {"IP": host_mac.get('host'), "MAC": host_mac.get('mac'),
                     "NIC manufacturer": host_mac.get('company')})
                # 存储部分
                ipaddress = host_mac.get('host')
                result = self.add_host(ipaddress, source=self.host_ipaddress, linktype="scan", data={"method": "arp"})
                # -1端口存储mac地址 -2端口存储网卡厂商
                self.add_portservice(ipaddress, 0, banner={'mac': host_mac.get('mac')}, service="MAC")
            self.log_table(data_zh, data_en)

        except Exception as E:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_except(str(E), str(E))
