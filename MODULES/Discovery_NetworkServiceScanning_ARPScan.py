# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

from Lib.ModuleAPI import *


class PostModule(PostMSFRawModule):
    NAME = "内网ARP扫描"
    DESC = "目标内网的ARP扫描,所有ARP请求与回复目标内网.\n" \
           "ARP消息只证明此主机存活,不会探测端口.\n" \
           "如其他模块需要连接发现的主机,请使用Session添加对应路由或Socks代理"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1046"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/pf9z8a"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1046/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionIPAddressRange(name='address_range', name_tag="IP列表", desc="IP列表(支持1.1.1.1,2.2.2.2,3.3.3.3-3.3.3.10格式输入)",
                             required=True),
        OptionIntger(name='threads', name_tag="扫描线程数", desc="扫描线程数(最大值10)", required=True, default=10),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.type = "post"
        self.mname = "windows/gather/arp_scanner_api"

    def check(self):
        """执行前的检查函数"""

        self.session = Session(self._sessionid)
        if self.session.is_windows is not True:
            return False, "此模块只支持windows平台meterpreter类型的session"

        address_range = self.param_address_range('address_range')
        if len(address_range) > 256:
            return False, "扫描IP范围过大(超过256),请缩小范围"
        elif len(address_range) < 0:
            return False, "输入的IP列表格式有误,请重新输入"
        self.set_option('RHOSTS', ", ".join(address_range))

        threads = self.param('threads')
        # 检查port_list
        if threads <= 0 or threads > 20:
            return False, "输入的扫描线程数有误(最大值10),请重新输入"
        self.set_option('THREADS', threads)

        return True, None

    def callback(self, status, message, data):
        if status is not True:
            self.log_error("模块执行失败,失败原因:{}".format(message))
            return
        try:
            host_mac_list = data
            self.log_status("扫描结果:")
            for host_mac in host_mac_list:
                # 输出部分
                tmpstr = "IP地址: {} MAC: {} 网卡厂商:{}".format(host_mac.get('host'), host_mac.get('mac'),
                                                           host_mac.get('company'))
                self.log_good(tmpstr)
                # 存储部分
                hid = self.add_host(host_mac.get('host'))
                # -1端口存储mac地址 -2端口存储网卡厂商
                self.add_portservice(hid, 0,
                                     proxy={'type': 'Session',
                                            'data': {'session_host': self.session.session_host,
                                                     'sessionid': self._sessionid}},
                                     banner={'mac': host_mac.get('mac')}, service="MAC")

        except Exception as E:
            self.log_error("模块执行失败,失败原因:{}".format(E))
