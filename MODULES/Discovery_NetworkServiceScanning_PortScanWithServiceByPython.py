# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :

import base64
import json

from Lib.ModuleAPI import *


class PostModule(PostMSFPythonWithParamsModule):
    NAME = "内网端口扫描与服务识别"
    DESC = "扫描内网中开放的TCP端口,识别已发现端口的服务,软件,版本等\n" \
           "所有扫描的网络流量在目标内网,\n如其他模块需要连接发现的服务,请添加对应路由及Socks代理"
    MODULETYPE = TAG2CH.Discovery
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1046"]  # ATTCK向量
    README = ["https://www.yuque.com/funnywolfdoc/viperdoc/zx9akt"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1046/"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='startip', name_tag="起始IP", required=True, desc="扫描的起始IP"),
        OptionStr(name='stopip', name_tag="结束IP", required=True, desc="扫描的结束IP"),
        OptionStr(name='port_list', name_tag="端口列表", required=True, desc="扫描的端口,以逗号分隔(例如22,80,445)",
                  default="21,22,80,88,139,445,1433,3306,3389,6379,7001,8080,8443", option_length=24),
        OptionIntger(name='timeout', name_tag="模块超时时间(秒)", desc="模块执行的超时时间", required=True, default=3600),
        OptionIntger(name='connect_time_out', name_tag="连接超时时间(毫秒)", desc="网络扫描过程中每个网络连接的超时时间,请依据主机内网网络环境进行调整",
                     default=500),
        OptionIntger(name='max_threads', name_tag="扫描线程数", desc="扫描线程数(最大值20)", default=10),
    ])

    def __init__(self, sessionid, hid, custom_param):
        super().__init__(sessionid, hid, custom_param)
        self.set_script("portScanWithService.py")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        # session 检查
        self.session = Session(self._sessionid)
        if self.session.is_alive is not True:
            return False, "此session不可用"

        startip = self.param('startip')
        stopip = self.param('stopip')
        port_list = self.param('port_list')
        timeout = self.param('timeout')
        connect_time_out = self.param('connect_time_out')
        max_threads = self.param('max_threads')

        # 检查ip地址
        try:
            ipnum = self.dqtoi(stopip) - self.dqtoi(startip)
            if ipnum > 256:
                return False, "扫描IP范围过大(超过256),请缩小范围"
            elif ipnum < 0:
                return False, "输入的起始IP与结束IP有误,请重新输入"
            self.set_script_param('startip', startip)
            self.set_script_param('stopip', stopip)
        except Exception as E:
            return False, "输入的IP格式有误,请重新输入"
        # 检查port_list
        try:
            list_str = "[{}]".format(port_list)
            port_list_net = json.loads(list_str)
            if len(port_list_net) > 100:
                return False, "扫描端口数量过大(超过100),请缩小范围"
            elif len(port_list_net) <= 0:
                return False, "输入的端口列表有误,请重新输入"
            port_list_tmp = port_list_net
            for port in port_list_tmp:
                if 0 < port <= 65535:
                    pass
                else:
                    port_list_net.remove(port)
            self.set_script_param('port_list', port_list_net)
        except Exception as E:
            return False, "输入的端口列表有误,请重新输入"

        # 检查timeout
        if timeout <= 0 or timeout > 3600:
            return False, "输入的模块超时时间有误(最大值3600),请重新输入"
        if connect_time_out <= 0 or connect_time_out > 3000:
            return False, "输入的连接超时时间有误(最大值3000),请重新输入"
        if max_threads <= 0 or max_threads > 20:
            return False, "输入的扫描线程数有误(最大值20),请重新输入"

        bad_cost = ipnum * len(port_list_net) * connect_time_out / 1000 / 20
        if bad_cost + 30 > timeout:  # 模块编译re需要时间,上传脚本需要时间
            return False, "输入的模块超时时间过短,请设置为大于 {} 的值".format(int(bad_cost) + 30)
        self.set_script_param('time_out', connect_time_out / 1000)
        self.set_script_param('max_threads', max_threads)
        self.set_script_timeout(timeout)

        return True, None

    @staticmethod
    def dqtoi(dq):
        """Return an integer value given an IP address as dotted-quad string."""
        octets = dq.split(".")
        if len(octets) != 4:
            raise ValueError
        for octet in octets:
            if int(octet) > 255:
                raise ValueError
        return (int(octets[0]) << 24) + \
               (int(octets[1]) << 16) + \
               (int(octets[2]) << 8) + \
               (int(octets[3]))

    def callback(self, status, message, data):
        if status:
            try:
                result = base64.b64decode(bytes(data, encoding="utf8")).decode('ascii')
                portservice_list = json.loads(result)
            except Exception as E:
                self.log_error("脚本输出解析失败")
                self.log_error(E)
                self.log_error(data)
                return

            if len(portservice_list) == 0:
                self.log_status("脚本执行完成,但是未扫描到有效数据,可能是由于对方网络关闭,请检查主机netstat信息后重试")
                self.log_status("如果确认网络连接正常但扫描无结果,请使用Meterpreter命令行中的'重置python插件功能'重置后重新扫描")
                return
            self.log_status("扫描结果")
            for portservice in portservice_list:
                # 输出部分

                try:
                    tmpService = portservice.get('banner').get('service')
                    tmpBanner = portservice.get('banner').get('versioninfo')
                except Exception as E:
                    tmpService = ""
                    tmpBanner = {}
                if tmpService is None:
                    tmpService = ""
                if tmpBanner is None:
                    tmpBanner = {}

                tmpstr = "IP地址: {} 端口: {} 协议:{} 服务:{}".format(portservice.get('host'), portservice.get('port'),
                                                              portservice.get('proto'),
                                                              tmpService)
                self.log_good(tmpstr)
                # 存储部分
                hid = self.add_host(portservice.get('host'))
                self.add_portservice(hid=hid,
                                     port=portservice.get('port'),
                                     proxy={
                                         'type': 'Session',
                                         'data':
                                             {
                                                 'session_host': self.session.session_host,
                                             }
                                     },
                                     banner=tmpBanner, service=tmpService)
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
