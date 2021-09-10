# -*- coding: utf-8 -*-
# @File  : SimplePostPythonModule.py
# @Date  : 2019/1/12
# @Desc  :


import base64
import json

from Lib.ModuleAPI import *


class PostModule(PostMSFPythonWithParamsModule):
    NAME_ZH = "内网Ping扫描"
    DESC_ZH = "通过ICMP协议(Ping)获取内网存活主机信息."

    NAME_EN = "Intranet Ping Scan"
    DESC_EN = "Obtain the information of the live hosts on the intranet through the ICMP protocol (Ping)."

    MODULETYPE = TAG2TYPE.Discovery
    PLATFORM = ["Windows", "Linux"]  # 平台
    PERMISSIONS = ["User", "Administrator", "SYSTEM", "Root"]  # 所需权限
    ATTCK = ["T1046"]  # ATTCK向量
    README = ["https://www.yuque.com/vipersec/module/bs3e7t"]
    REFERENCES = ["https://github.com/samuel/python-ping"]
    AUTHOR = "Viper"

    OPTIONS = register_options([
        OptionStr(name='ipstr', tag_zh="IP地址", required=True,
                  desc_zh="扫描IP地址列表(10.10.10.10,10.10.11-13,10.10.11.1/24)"),

        OptionInt(name='connect_time_out', tag_zh="连接超时时间(毫秒)", desc_zh="网络扫描过程中每个网络连接的超时时间,请依据主机内网网络环境进行调整(通常小于500ms)",
                  default=100),
        OptionInt(name='timeout', tag_zh="模块执行超时时间(秒)", desc_zh="模块执行的超时时间", required=True, default=600),

        OptionInt(name='max_threads', tag_zh="扫描线程数", desc_zh="扫描线程数(最大值20)", default=10),
    ])

    def __init__(self, sessionid, ipaddress, custom_param):
        super().__init__(sessionid, ipaddress, custom_param)
        self.set_script("ping.py")  # 设置目标机执行的脚本文件

    def check(self):
        """执行前的检查函数"""
        # session 检查

        self.session = Session(self._sessionid)
        if self.session.is_alive is not True:
            return False, "当前session不可用"

        # 参数检查
        ipstr = self.param('ipstr')
        timeout = self.param('timeout')
        connect_time_out = self.param('connect_time_out')
        max_threads = self.param('max_threads')

        try:

            iplist = self.str_to_ips(ipstr)

            if len(iplist) > 510:
                return False, "扫描IP范围过大(超过510),请缩小范围"
            elif len(iplist) < 0:
                return False, "输入的IP地址格式有误,未识别到有效IP地址,请重新输入"
            self.set_script_param('ipstr', ipstr)
        except Exception as E:
            return False, "输入的IP格式有误,请重新输入"
        if self.param('port') not in [139, 445]:
            self.set_script_param('port', 139)
        else:
            self.set_script_param('port', self.param("port"))

        if timeout <= 0 or timeout > 3600:
            return False, "输入的模块超时时间有误(最大值3600),请重新输入"
        if connect_time_out <= 0 or connect_time_out > 3000:
            return False, "输入的连接超时时间有误(最大值3000),请重新输入"
        if max_threads <= 0 or max_threads > 20:
            return False, "输入的扫描线程数有误(最大值20),请重新输入"

        self.set_script_param('time_out', connect_time_out / 1000)
        # self.set_script_param('max_threads', max_threads)
        self.set_script_timeout(timeout)

        # return False, None
        return True, None

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
                self.log_info("脚本执行完成,但是未扫描到有效数据,可能是由于对方网络关闭,请检查主机netstat信息后重试")
                self.log_info("如果确认网络连接正常但扫描无结果,请使用Meterpreter命令行中的'重置python插件功能'重置后重新扫描")
                return

            self.log_info("扫描结果")
            for portservice in portservice_list:
                # 输出部分
                ipaddress = portservice.get("ipaddress")
                delay = portservice.get("delay")
                # 新增主机
                result = self.add_host(ipaddress, source=self.host_ipaddress, linktype="scan",
                                       data={"method": "ping"})
                self.log_raw(f"{ipaddress}  {delay * 1000}ms")
        else:
            self.log_error("模块执行失败")
            self.log_error(message)
