# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


import base64
import json

from Lib.ModuleAPI import *


class PostModule(PostMSFPythonWithParamsModule):
    NAME_ZH = "内网端口扫描"
    DESC_ZH = "目标内网的端口扫描.\n" \
              "扫描脚本在目标主机执行(Windows内存执行,Linux使用Python解释器),所有扫描的网络流量在目标内网.\n" \
              "如其他模块需要连接发现的服务,请使用此Session添加对应路由或使用Socks代理"

    NAME_EN = "Intranet port scan"
    DESC_EN = "Port scan of the target intranet.\n" \
              "The scanning script is executed on the target host (Windows memory execution, Linux uses the Python interpreter), and all scanned network traffic is on the target intranet.\n" \
              "If other modules need to connect to the discovered service, please use this Session to add the corresponding route or use Socks proxy"

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", ]  # 所需权限
    ATTCK = ["T1046"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/qcgtcn"]
    REFERENCES = ["https://attack.mitre.org/techniques/T1046/"]
    AUTHOR = ["Viper"]

    OPTIONS = register_options([
        OptionText(name='ipstr',
                   tag_zh="IP地址",
                   desc_zh="扫描IP地址列表(10.10.10.10,10.10.11-13,10.10.11.1/24)",
                   tag_en="IP address",
                   desc_en="Scan the list of IP addresses (10.10.10.10, 10.10.11-13, 10.10.11.1/24)",
                   required=True,
                   ),
        OptionStr(name='port_list',
                  tag_zh="端口列表", required=True, desc_zh="扫描的端口,以逗号分隔(例如22,80,445)",
                  tag_en="Port list", desc_en="Scanned ports, separated by commas (e.g. 22, 80, 445)",
                  length=24, default="21,22,80,88,139,445,1433,3306,3389,6379,7001,8080,8443"),
        OptionInt(name='timeout',
                  tag_zh="模块超时时间(秒)", desc_zh="模块执行的超时时间",
                  tag_en="Module timeout time (seconds)", desc_en="Module execution timeout",
                  required=True, default=600),
        OptionInt(name='connect_time_out',
                  tag_zh="连接超时时间(毫秒)", desc_zh="网络扫描过程中每个网络连接的超时时间,请依据主机内网网络环境进行调整",
                  tag_en="Connection timeout (millisecond)",
                  desc_en="Please adjust the timeout time of each network connection during the network scanning process according to the host's intranet network environment",
                  default=50),
        OptionInt(name='max_threads',
                  tag_zh="扫描线程数", desc_zh="扫描线程数(最大值20)",
                  tag_en="Number of scanning threads", desc_en="Number of scanning threads (maximum 20)",
                  default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("portScan.py")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        # session 检查

        self.session = Session(self._sessionid)
        if self.session.is_alive is not True:
            return False, "Session不可用", "Session is unavailable"

        # 参数检查
        ipstr = self.param('ipstr')
        port_list = self.param('port_list')
        timeout = self.param('timeout')
        connect_time_out = self.param('connect_time_out')
        max_threads = self.param('max_threads')
        # 检查ip地址

        try:
            iplist = self.str_to_ips(ipstr)
            if len(iplist) > 510:
                return False, "扫描IP范围过大(超过510)", "Scanning IP range is too large (more than 510)"
            elif len(iplist) < 0:
                return False, "输入的IP地址格式有误,未识别到有效IP地址", "The format of the entered IP address is incorrect, and a valid IP address is not recognized"
            self.set_script_param('ipstr', ipstr)
        except Exception as E:
            return False, "输入的IP格式有误", "The entered IP format is incorrect"

        # 检查port_list
        try:
            list_str = f"[{port_list}]"
            port_list_net = json.loads(list_str)
            if len(port_list_net) > 100:
                return False, "扫描端口数量过大(超过100)", "The number of scanning ports is too large (more than 100)"
            elif len(port_list_net) <= 0:
                return False, "输入的端口列表有误", "The port list entered is incorrect"
            port_list_tmp = port_list_net
            for port in port_list_tmp:
                if 0 < port <= 65535:
                    pass
                else:
                    port_list_net.remove(port)
            self.set_script_param('port_list', port_list_net)
        except Exception as E:
            return False, "输入的端口列表有误,请重新输入", "The port list entered is incorrect"
        # 检查timeout
        if timeout <= 0 or timeout > 3600:
            return False, "输入的模块超时时间有误(最大值600)", "ErroThe entered module timeout time is incorrect (maximum 600)r"
        if connect_time_out <= 0 or connect_time_out > 3000:
            return False, "输入的连接超时时间有误(最大值3000)", "The connection timeout entered is incorrect (maximum 3000)"
        if max_threads <= 0 or max_threads > 20:
            return False, "输入的扫描线程数有误(最大值20)", "The number of scan threads entered is incorrect (maximum 20)"

        self.set_script_param('time_out', connect_time_out / 1000)
        self.set_script_param('max_threads', max_threads)
        self.set_script_timeout(timeout)

        return True, None

    def callback(self, status, message, data):
        if status:
            try:
                result = base64.b64decode(bytes(data, encoding="utf8")).decode('ascii')
                portservice_list = json.loads(result)
            except Exception as E:
                self.log_error("脚本输出解析失败", "Script output parsing failed")
                self.log_error(data, data)
                self.log_except(str(E), str(E))
                return
            if len(portservice_list) == 0:
                self.log_info("脚本执行完成,但是未扫描到有效数据,可能是由于对方网络关闭,请检查主机netstat信息后重试",
                              "The script execution is complete, but no valid data is scanned. It may be because the other party's network is closed. Please check the host's netstat information and try again")
                self.log_info("如果确认网络连接正常但扫描无结果,请使用Meterpreter命令行中的'重置python插件'功能重置后重新扫描",
                              "If you confirm that the network connection is normal but the scan has no results, please use the'reset python plugin' function in the Meterpreter command line to rescan after reset")
                return

            data_zh = []
            data_en = []

            for portservice in portservice_list:
                # 输出部分
                data_zh.append(
                    {"IP": portservice.get('host'), "端口": portservice.get('port'), "协议": portservice.get('proto')})
                data_en.append(
                    {"IP": portservice.get('host'), "Port": portservice.get('port'),
                     "Protocol": portservice.get('proto')})

                # 存储部分
                ipaddress = portservice.get('host')
                result = self.add_host(ipaddress, source=self.host_ipaddress, linktype="scan",
                                       data={"method": "portscan"})
                self.add_portservice(ipaddress, portservice.get('port'), banner={}, service="")
            self.log_table(data_zh, data_en)
        else:
            self.log_error("模块执行失败", "Module execution failed")
            self.log_error(message, message)
